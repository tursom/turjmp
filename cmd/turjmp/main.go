package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/logging"
	// SSH 代理服务实现，处理入站 SSH 连接并代理到目标主机
	sshproxy "github.com/tursom/turjmp/internal/proxy/ssh"
	"github.com/tursom/turjmp/internal/rbac"
	"github.com/tursom/turjmp/internal/repository"
	"github.com/tursom/turjmp/internal/server"
	"github.com/tursom/turjmp/internal/service"
)

type roles struct {
	api      bool
	sshProxy bool
	dbProxy  bool
	rdpProxy bool
}

func main() {
	var configPath string
	var selected roles
	var all bool
	var migrate string
	flag.StringVar(&configPath, "config", "configs/config.dev.yaml", "config file path")
	flag.BoolVar(&selected.api, "api", false, "enable API server")
	flag.BoolVar(&selected.sshProxy, "ssh-proxy", false, "enable SSH proxy")
	flag.BoolVar(&selected.dbProxy, "db-proxy", false, "enable database proxy")
	flag.BoolVar(&selected.rdpProxy, "rdp-proxy", false, "enable RDP proxy")
	flag.BoolVar(&all, "all", false, "enable API and all proxy roles")
	flag.StringVar(&migrate, "migrate", "", "run migration command: up, down, or status")
	flag.Parse()

	if all {
		selected = roles{api: true, sshProxy: true, dbProxy: true, rdpProxy: true}
	}
	if migrate == "" && !selected.any() {
		fatalf("select at least one role: --api, --ssh-proxy, --db-proxy, --rdp-proxy, or --all")
	}

	cfg, err := config.Load(configPath)
	must(err)

	log, err := logging.New(cfg.Logging)
	must(err)
	defer func() { _ = log.Sync() }()

	if migrate != "" {
		must(runMigration(cfg, migrate))
		return
	}

	ctx, stop := server.SignalContext()
	defer stop()

	errCh := make(chan error, 1)
	var apiServer *server.Server
	var apiDB *repository.DB
	// SSH 代理服务器实例，监听并代理 SSH 连接
	var sshServer *sshproxy.Server

	if selected.api {
		apiServer, apiDB, err = startAPI(cfg, log)
		must(err)
		defer apiDB.Close()
		go func() {
			log.Info("api_server_start", zap.String("addr", cfg.HTTP.Addr))
			if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("api server: %w", err)
				return
			}
		}()
	}
	// SSH 代理角色启停：初始化 SSH 代理服务器并在 goroutine 中启动监听，异常时写入错误通道
	if selected.sshProxy {
		sshServer, err = sshproxy.NewServer(cfg)
		must(err)
		go func() {
			log.Info("ssh_proxy_start", zap.String("addr", cfg.Proxy.SSH.Addr), zap.String("api_base_url", cfg.Proxy.APIBaseURL))
			if err := sshServer.Start(ctx); err != nil {
				errCh <- fmt.Errorf("ssh proxy: %w", err)
			}
		}()
	}
	startProxyStubs(selected, log)

	select {
	case <-ctx.Done():
		log.Info("shutdown_begin")
	case err := <-errCh:
		log.Error("runtime_error", zap.Error(err))
		stop()
		log.Info("shutdown_begin")
	}

	if apiServer != nil {
		if err := server.Shutdown(context.Background(), cfg.HTTP.ShutdownTimeout(), apiServer.Shutdown); err != nil {
			log.Error("api_shutdown_failed", zap.Error(err))
		}
	}
	// 优雅关闭 SSH 代理服务器，释放端口和连接资源
	if sshServer != nil {
		sshServer.Stop()
	}
	log.Info("shutdown_complete")
}

func (r roles) any() bool {
	return r.api || r.sshProxy || r.dbProxy || r.rdpProxy
}

func startAPI(cfg config.Config, log *zap.Logger) (*server.Server, *repository.DB, error) {
	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	store := repository.NewStore(db)
	if err := store.BootstrapDefaults(); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	box, err := crypto.NewSecretBox(cfg.Security.EncryptionKey)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	jwtMgr, err := auth.NewJWTManager(cfg.JWT)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if err := ensureKeyDirs(cfg.JWT.PrivateKeyPath, cfg.JWT.PublicKeyPath); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	enforcer, err := rbac.NewEnforcer(store)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	settingService := service.NewSettingService(store, box)
	if err := settingService.Load(); err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	h := &handler.Handler{
		Auth:        service.NewAuthService(store, jwtMgr, cfg),
		Users:       service.NewUserService(store, cfg.Security.PasswordMinLength),
		Assets:      service.NewAssetService(store, box),
		Permissions: service.NewPermissionService(store),
		Tokens:      service.NewTokenService(store, box, cfg.ProxyAuth),
		Settings:    settingService,
		Sessions:    service.NewSessionService(store),
		// 主机密钥管理服务，提供 SSH HostKey 的生成、存储和查询
		HostKeys:    service.NewHostKeyService(store),
		Store:       store,
		Enforcer:    enforcer,
	}
	return server.New(cfg, log, db, h), db, nil
}

// startProxyStubs 为非 SSH 的代理角色（DB、RDP）输出占位日志，表示这些角色尚未实现实际逻辑
func startProxyStubs(selected roles, log *zap.Logger) {
	if selected.dbProxy {
		log.Info("db_proxy_stub_started")
	}
	if selected.rdpProxy {
		log.Info("rdp_proxy_stub_started")
	}
}

func runMigration(cfg config.Config, command string) error {
	db, err := repository.NewDB(cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.SetDialect(dialect(cfg.Database.Driver)); err != nil {
		return err
	}
	goose.SetBaseFS(os.DirFS("."))

	switch command {
	case "up":
		return goose.Up(db.DB.DB, cfg.Database.MigrationsDir)
	case "down":
		return goose.Down(db.DB.DB, cfg.Database.MigrationsDir)
	case "status":
		return goose.StatusContext(context.Background(), db.DB.DB, cfg.Database.MigrationsDir)
	default:
		return fmt.Errorf("unknown migration command: %s", command)
	}
}

func dialect(driver string) string {
	if driver == "postgres" {
		return "postgres"
	}
	return "sqlite3"
}

func ensureKeyDirs(privatePath, publicPath string) error {
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(publicPath), 0o755)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
