// 主程序入口：turjmp 通用代理网关
// 支持 API 服务器、SSH 代理、数据库代理和 RDP 代理四种运行角色
// 通过 --api / --ssh-proxy / --db-proxy / --rdp-proxy / --all 选择角色组合
// 还支持 --migrate 子命令执行独立的数据迁移操作而不启动代理服务
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

	"github.com/tursom/turjmp/internal/api"
	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/logging"
	// dbproxy 数据库代理服务实现，封装 MySQL 协议代理和 Web DB 终端功能
	dbproxy "github.com/tursom/turjmp/internal/proxy/db"
	// RDP Web 代理服务实现，基于 guacd 提供浏览器 RDP 访问与录制
	rdpproxy "github.com/tursom/turjmp/internal/proxy/rdp"
	// SSH 代理服务实现，处理入站 SSH 连接并代理到目标主机
	sshproxy "github.com/tursom/turjmp/internal/proxy/ssh"
	"github.com/tursom/turjmp/internal/rbac"
	"github.com/tursom/turjmp/internal/repository"
	"github.com/tursom/turjmp/internal/server"
	"github.com/tursom/turjmp/internal/service"
)

// roles 结构体表示通过命令行选择的运行角色
// 角色之间相互独立，可任意组合启用：
//
//	api      - HTTP API 服务器，提供 Web 管理界面和后端 REST 接口
//	sshProxy - SSH 代理服务器，处理入站 SSH 连接并转发到目标主机
//	dbProxy  - 数据库代理服务器，处理入站 MySQL/PostgreSQL 连接
//	rdpProxy - RDP Web 代理服务器，通过 guacd 代理浏览器 RDP 会话
type roles struct {
	api      bool
	sshProxy bool
	dbProxy  bool
	rdpProxy bool
}

// main 函数是程序入口，完整启动流程如下：
//  1. 解析命令行参数（flag.Parse）—— 获取配置路径、角色选择和迁移命令
//  2. 加载配置文件（config.Load）—— 读取 YAML 配置，构建运行时配置结构
//  3. 初始化日志系统（logging.New）—— 根据配置初始化 zap 日志器
//  4. 若指定了 -migrate，执行数据库迁移命令后直接退出（不启动任何服务）
//  5. 创建带信号监听的 context（server.SignalContext）—— 监听 SIGINT/SIGTERM
//  6. 按选中的角色启动对应服务，API 和 SSH 代理在独立 goroutine 中运行
//  7. 通过 errCh 通道监听 goroutine 运行时错误
//  8. select 阻塞等待关闭信号（系统信号或运行时错误），收到后执行优雅关闭
func main() {
	var configPath string
	var selected roles
	var all bool
	var migrate string
	// 命令行参数定义：
	//   --config    string  配置文件路径，默认 configs/config.dev.yaml
	//   --api       bool    启用 API 服务器（HTTP REST + Web 管理界面）
	//   --ssh-proxy bool    启用 SSH 代理服务器（监听并转发 SSH 连接）
	//   --db-proxy  bool    启用数据库代理（当前仅占位）
	//   --rdp-proxy bool    启用 RDP Web 代理服务器
	//   --all       bool    同时启用以上所有角色
	//   --migrate   string  数据库迁移命令：up（应用迁移）/ down（回滚）/ status（查看状态）
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

	// errCh 是 goroutine 错误传递通道，缓冲大小为 1
	// 各后台 goroutine（API 服务、SSH 代理等）在发生不可恢复错误时，
	// 将错误发送到此通道，触发主 goroutine 执行优雅关闭
	// 缓冲大小 1 确保至少一个 goroutine 能非阻塞地发送错误
	errCh := make(chan error, 1)
	var apiServer *server.Server
	var apiDB *repository.DB
	// SSH 代理服务器实例，监听并代理 SSH 连接
	var sshServer *sshproxy.Server
	// dbServer 持有数据库代理服务器实例，管理 MySQL 原生协议代理的启动和停止生命周期
	var dbServer *dbproxy.Server
	// rdpServer 持有 RDP Web 代理服务器实例，管理 guacd WebSocket 桥接生命周期
	var rdpServer *rdpproxy.Server

	if selected.api {
		apiServer, apiDB, err = startAPI(cfg, log, api.RouterOptions{ExpectRDPProxy: selected.rdpProxy})
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
	// 数据库代理角色启停：初始化 MySQL 原生协议代理服务器，在 goroutine 中监听配置地址，
	// 拦截 MySQL 客户端连接握手并将 SQL 流量代理到目标数据库，异常时写入错误通道
	if selected.dbProxy {
		dbServer = dbproxy.NewServer(cfg)
		go func() {
			log.Info("db_proxy_start", zap.String("addr", cfg.Proxy.DB.MySQLListenAddr()))
			if err := dbServer.Start(ctx); err != nil {
				errCh <- fmt.Errorf("db proxy: %w", err)
			}
		}()
	}
	// RDP 远程桌面代理角色启停：初始化 RDP Web 代理服务器，在 goroutine 中监听 WebSocket 和 guacd 双端口，
	// 将浏览器 RDP 流量（含音频/视频/粘贴板）代理到远程 Windows 主机，异常时写入错误通道
	if selected.rdpProxy {
		rdpServer = rdpproxy.NewServer(cfg)
		go func() {
			log.Info("rdp_proxy_start", zap.String("addr", cfg.Proxy.RDP.ListenAddr()), zap.String("guacd_addr", cfg.Proxy.RDP.GuacdListenAddr()))
			if err := rdpServer.Start(ctx); err != nil {
				errCh <- fmt.Errorf("rdp proxy: %w", err)
			}
		}()
	}

	// 优雅关闭触发条件（二选一，select 阻塞直到任一事件发生）：
	//   case <-ctx.Done():  收到 SIGINT（Ctrl+C）或 SIGTERM 系统信号
	//   case err := <-errCh: 后台 goroutine 发生不可恢复的运行时错误
	// 运行时错误路径会先调用 stop() 取消 context（通知其他 goroutine 停止），
	// 然后进入统一的关闭流程，两者最终执行相同的资源释放逻辑
	select {
	case <-ctx.Done():
		log.Info("shutdown_begin")
	case err := <-errCh:
		log.Error("runtime_error", zap.Error(err))
		stop()
		log.Info("shutdown_begin")
	}

	// 优雅关闭 API 服务器：使用配置的超时时间等待进行中的请求完成
	if apiServer != nil {
		if err := server.Shutdown(context.Background(), cfg.HTTP.ShutdownTimeout(), apiServer.Shutdown); err != nil {
			log.Error("api_shutdown_failed", zap.Error(err))
		}
	}
	// 优雅关闭 SSH 代理服务器，释放端口和连接资源
	if sshServer != nil {
		sshServer.Stop()
	}
	// 优雅关闭数据库代理服务器，释放 MySQL 监听端口和所有活跃的连接资源
	if dbServer != nil {
		dbServer.Stop()
	}
	// 优雅关闭 RDP Web 代理服务器，释放 WebSocket 监听端口和 guacd 会话资源
	if rdpServer != nil {
		rdpServer.Stop()
	}
	log.Info("shutdown_complete")
}

// any 方法检查 roles 中是否至少有一个角色被选中
// 用于在未指定 --migrate 时强制验证用户至少启用了一个角色
// 若所有角色均为 false 且无迁移命令，程序将报错退出
func (r roles) any() bool {
	return r.api || r.sshProxy || r.dbProxy || r.rdpProxy
}

// startAPI 初始化 API 服务器及其完整依赖链
// 初始化顺序严格遵守依赖关系，不可调换：
//  1. 数据库连接（repository.NewDB）     —— 一切持久化操作的基础
//  2. 数据仓库（repository.NewStore）    —— 封装所有数据库查询，依赖 db
//  3. 加密模块（crypto.NewSecretBox）    —— 机密数据加解密，依赖配置中的加密密钥
//  4. JWT 管理器（auth.NewJWTManager）   —— 身份认证令牌生成与验证
//  5. 密钥目录（ensureKeyDirs）          —— 确保 JWT 私钥/公钥文件路径可写
//  6. RBAC 执行器（rbac.NewEnforcer）    —— 基于角色的访问控制，依赖 store
//  7. 设置服务（settingService.Load）    —— 加载全局系统设置，依赖 store 和 box
//  8. HTTP 处理器（handler.Handler）     —— 注册所有业务服务到处理器
//  9. HTTP 服务器（server.New）          —— 组装中间件、路由并返回可启动的服务器
//
// 任一步骤初始化失败都会关闭已打开的数据库连接并向上返回错误
func startAPI(cfg config.Config, log *zap.Logger, routerOptions api.RouterOptions) (*server.Server, *repository.DB, error) {
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
		// 注入运行时配置，供 Handler 生成原生客户端连接地址时使用
		Config:         cfg,
		Auth:           service.NewAuthService(store, jwtMgr, cfg),
		Users:          service.NewUserService(store, cfg.Security.PasswordMinLength),
		RDPCredentials: service.NewRDPProxyCredentialService(store, cfg.Security.PasswordMinLength),
		NativeRDP:      service.NewNativeRDPResolverService(store, box, cfg.Security.PasswordMinLength),
		Assets:         service.NewAssetService(store, box),
		Permissions:    service.NewPermissionService(store),
		Tokens:         service.NewTokenService(store, box, cfg.ProxyAuth),
		Settings:       settingService,
		Sessions:       service.NewSessionService(store),
		// 主机密钥管理服务，提供 SSH HostKey 的生成、存储和查询
		HostKeys: service.NewHostKeyService(store),
		Store:    store,
		Enforcer: enforcer,
	}
	return server.New(cfg, log, db, h, routerOptions), db, nil
}

// runMigration 执行数据库迁移操作
// 创建独立的数据库连接，使用 goose 库管理迁移版本
// command 参数支持三种操作：
//
//	"up"     - 应用所有未执行的迁移（正向迁移）
//	"down"   - 回滚最近一次已执行的迁移
//	"status" - 查看迁移状态（列出已执行和未执行的迁移）
//
// 迁移文件存放于 cfg.Database.MigrationsDir 指定的目录中
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

// dialect 将配置中的数据库驱动名称映射为 goose 库内部使用的方言字符串
// "postgres" 保持不变，其他驱动（如 sqlite）统一映射为 "sqlite3"
// goose 库通过方言字符串选择对应的 SQL 语法生成器
func dialect(driver string) string {
	if driver == "postgres" {
		return "postgres"
	}
	return "sqlite3"
}

// ensureKeyDirs 确保 JWT 私钥和公钥文件所在的父目录存在
// 私钥目录使用 0700 权限（仅 owner 可读写执行），防止其他用户访问私钥
// 公钥目录使用 0755 权限（owner 全权限，其他人可读取执行），允许外部进程读取公钥
func ensureKeyDirs(privatePath, publicPath string) error {
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(publicPath), 0o755)
}

// must 是致命错误辅助函数：如果 err 不为 nil，打印错误并立即以状态码 1 退出
// 仅用于初始化阶段（配置加载、日志初始化等不可恢复的错误）
func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

// fatalf 格式化错误信息到标准错误输出并以状态码 1 退出程序
// 用于程序无法继续运行时的致命错误终止
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
