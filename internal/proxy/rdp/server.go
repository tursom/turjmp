package rdpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/wwt/guac"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/health"
	"github.com/tursom/turjmp/internal/recorder"
)

// Server exposes /ws/rdp and bridges Guacamole WebSocket traffic to guacd.
type Server struct {
	cfg     config.Config           // 全局配置（监听地址、超时、限制阈值等）
	api     apiClient               // 后端 API 客户端（token 验证、session 生命周期）
	storage recorder.StorageBackend // 录制文件持久化存储
	limit   *limiter                // 并发会话限流器
	http    *http.Server            // HTTP 服务器实例
	mu      sync.Mutex              // 并发保护锁
	native  *NativeEngineHandle     // 原生 RDP MITM 引擎进程句柄
}

// NewServer creates an RDP proxy server using backend API callbacks and local recording storage.
func NewServer(cfg config.Config) *Server {
	api := NewAPIClient(cfg)
	basePath := cfg.Proxy.RDP.RecordingDir()
	storage := recorder.NewLocalStorage(basePath)
	return NewServerWithDeps(cfg, api, storage)
}

// NewServerWithDeps creates an RDP proxy server with injectable dependencies for tests.
func NewServerWithDeps(cfg config.Config, api apiClient, storage recorder.StorageBackend) *Server {
	if storage == nil {
		storage = recorder.NewLocalStorage(cfg.Proxy.RDP.RecordingDir())
	}
	s := &Server{
		cfg:     cfg,
		api:     api,
		storage: storage,
		limit:   newLimiter(cfg.Proxy.RDP.ConnectionLimit()),
	}
	mux := http.NewServeMux()
	mux.Handle("/ws/rdp/", s.newWebSocketHandler())
	mux.Handle("/health", http.HandlerFunc(s.health))
	s.http = &http.Server{
		Addr:              cfg.Proxy.RDP.ListenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Start starts the RDP WebSocket HTTP listener and, when enabled, the native FreeRDP engine.
func (s *Server) Start(ctx context.Context) error {
	if err := ValidateNativeEngineConfig(s.cfg); err != nil {
		return err
	}
	errCh := make(chan error, 2)
	var nativeHandle *NativeEngineHandle
	if s.cfg.Proxy.RDP.NativeEnabled {
		engineCfg, err := NativeEngineConfigFromAppConfig(s.cfg, NativeFixedTarget{})
		if err != nil {
			return err
		}
		nativeHandle, err = NewFreeRDPEngine().Start(ctx, engineCfg)
		if err != nil {
			return err
		}
		s.setNativeHandle(nativeHandle)
		go func() {
			err := nativeHandle.Wait()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = &NativeEngineError{Kind: NativeEngineErrorExit, Op: "wait", Err: errors.New("process exited")}
			}
			errCh <- fmt.Errorf("native rdp engine: %w", err)
		}()
	}
	go func() {
		errCh <- s.http.ListenAndServe()
	}()
	cleanup := func() error {
		s.stopNativeEngine("proxy_shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout())
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
	select {
	case <-ctx.Done():
		if err := cleanup(); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		_ = cleanup()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Stop shuts down the RDP listener without waiting for the parent context.
func (s *Server) Stop() {
	s.stopNativeEngine("proxy_shutdown")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout())
	defer cancel()
	_ = s.http.Shutdown(shutdownCtx)
}

func (s *Server) setNativeHandle(handle *NativeEngineHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.native = handle
}

func (s *Server) stopNativeEngine(reason string) {
	s.mu.Lock()
	handle := s.native
	s.native = nil
	s.mu.Unlock()
	if s.cfg.Proxy.RDP.NativeEnabled && s.api != nil {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout())
		defer cancel()
		_ = s.api.FinishActiveNativeRDPSessions(ctx, reason)
	}
	if handle != nil {
		_ = handle.Stop()
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	components := map[string]health.Component{
		"web_rdp":    health.Ready(),
		"native_rdp": health.Disabled(),
	}
	if s.cfg.Proxy.RDP.NativeEnabled {
		components["native_rdp"] = s.nativeHealth()
	}
	ready := health.NewReadiness(components)
	status := http.StatusOK
	if ready.Status != health.StatusReady {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ready)
}

func (s *Server) nativeHealth() health.Component {
	if err := ValidateNativeEngineConfig(s.cfg); err != nil {
		return health.NotReady(err)
	}
	s.mu.Lock()
	handle := s.native
	s.mu.Unlock()
	if handle == nil || !handle.Running() {
		return health.NotReady(errors.New("native rdp engine is not running"))
	}
	return health.Ready()
}

// newWebSocketHandler 创建 WebSocket 处理器，将每个 WebSocket 连接委托给 connect 建立 guac 隧道。
func (s *Server) newWebSocketHandler() http.Handler {
	wsServer := guac.NewWebsocketServerWs(func(ws *websocket.Conn, r *http.Request) (guac.Tunnel, error) {
		return s.connect(ws, r)
	})
	return wsServer
}

func (s *Server) connect(ws *websocket.Conn, r *http.Request) (guac.Tunnel, error) {
	// 步骤1: 限流——获取会话槽位，超限则拒绝连接并释放 WebSocket
	if !s.limit.acquire() {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "RDP 会话过多"), time.Now().Add(time.Second))
		return nil, fmt.Errorf("RDP 会话过多")
	}
	// release 标志位：connect 中途失败时由 defer 释放限流槽位，成功时由 sessionTunnel.Close 接管
	release := true
	defer func() {
		if release {
			s.limit.release()
		}
	}()

	// 步骤2: 提取 URL 中的 token 参数
	token := r.URL.Query().Get("token")
	if token == "" {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "需要连接令牌"), time.Now().Add(time.Second))
		return nil, fmt.Errorf("需要连接令牌")
	}

	// 步骤3: 调用后端 API 验证 token，获取授权信息
	ctx := r.Context()
	auth, err := s.api.VerifyConnectionToken(ctx, token, r.RemoteAddr)
	if err != nil {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "token verification failed"), time.Now().Add(time.Second))
		return nil, err
	}
	// 步骤4: 校验授权结果——必须是 RDP 协议且含必要地址与凭据
	if err := validateRDPAuth(auth); err != nil {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "connection token protocol is not rdp"), time.Now().Add(time.Second))
		return nil, err
	}

	// 步骤5: 在后端创建 RDP 会话记录
	session, err := s.api.CreateSession(ctx, sessionInfo{
		UserID:        auth.UserID,
		AssetID:       auth.AssetID,
		AccountID:     auth.AccountID,
		Protocol:      "rdp",
		Type:          "rdp",
		ConnectMethod: "web_rdp",
		RemoteAddr:    r.RemoteAddr,
	})
	if err != nil {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "create RDP session failed"), time.Now().Add(time.Second))
		return nil, err
	}

	// 步骤6: 确保录制目录存在，以便后续 guacd 写入录制文件
	recordingName := strconv.FormatInt(session.SessionID, 10)
	if err := os.MkdirAll(s.cfg.Proxy.RDP.RecordingDir(), 0o755); err != nil {
		_ = s.api.FinishSession(context.Background(), session.SessionID, "")
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "prepare RDP recording failed"), time.Now().Add(time.Second))
		return nil, err
	}

	// 步骤7: 拨号连接 guacd
	conn, err := s.dialGuacd(ctx)
	if err != nil {
		_ = s.api.FinishSession(context.Background(), session.SessionID, "")
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "connect guacd failed"), time.Now().Add(time.Second))
		return nil, err
	}

	// 步骤8: 在 TCP 连接上创建 guac 流
	stream := guac.NewStream(conn, s.cfg.Proxy.RDP.IdleTimeout())
	// 步骤9: guac 握手——协商协议参数（分辨率、凭据、录制路径等）
	if err := stream.Handshake(s.guacdConfig(auth, r, recordingName)); err != nil {
		_ = stream.Close()
		_ = s.api.FinishSession(context.Background(), session.SessionID, "")
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "guacd handshake failed"), time.Now().Add(time.Second))
		return nil, err
	}

	// 步骤10: 构建 sessionTunnel 隧道——包装 guac 简易隧道，注入限流释放与 session 结束回调
	// 步骤11: 隧道由 WebSocket → guacd 桥接层持有，不再由本次 connect 管理生命周期
	// 步骤12: 设置 release=false，防止 defer 重复释放限流槽位（已转交 sessionTunnel）
	tunnel := &sessionTunnel{
		Tunnel:        guac.NewSimpleTunnel(stream),
		release:       s.limit.release,
		finish:        s.finishSession,
		sessionID:     session.SessionID,
		recordingName: recordingName,
	}
	release = false
	return tunnel, nil
}

// validateRDPAuth 校验 token 授权结果：协议必须为 RDP，且包含目标地址和用户名。
func validateRDPAuth(auth authResult) error {
	if !isRDPProtocol(auth.Target.Protocol) {
		return fmt.Errorf("连接令牌协议不是 RDP")
	}
	if auth.Target.Address == "" {
		return fmt.Errorf("需要 RDP 目标地址")
	}
	if auth.Account.Username == "" {
		return fmt.Errorf("需要 RDP 用户名")
	}
	return nil
}

// dialGuacd 通过 TCP 拨号连接到 guacd 守护进程。
func (s *Server) dialGuacd(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: s.cfg.Proxy.RDP.ConnectTimeout()}
	return dialer.DialContext(ctx, "tcp", s.cfg.Proxy.RDP.GuacdListenAddr())
}

// guacdConfig 构建 guacd 握手配置，从 URL 查询参数中提取分辨率/安全设置，映射授权信息为连接参数。
func (s *Server) guacdConfig(auth authResult, r *http.Request, recordingName string) *guac.Config {
	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = "rdp"
	// 从 URL 查询参数中解析可选显示参数（宽度、高度、DPI）
	cfg.OptimalScreenWidth = parsePositiveInt(r.URL.Query().Get("width"), cfg.OptimalScreenWidth)
	cfg.OptimalScreenHeight = parsePositiveInt(r.URL.Query().Get("height"), cfg.OptimalScreenHeight)
	cfg.OptimalResolution = parsePositiveInt(r.URL.Query().Get("dpi"), cfg.OptimalResolution)
	cfg.AudioMimetypes = []string{"audio/L16", "rate=44100", "channels=2"}
	cfg.ImageMimetypes = []string{"image/png", "image/jpeg"}
	// 将授权信息映射为 guacd 连接参数：主机、端口、凭据、安全选项、录制路径
	cfg.Parameters = map[string]string{
		"hostname":              auth.Target.Address,
		"port":                  strconv.Itoa(rdpTargetPort(auth.Target)),
		"username":              auth.Account.Username,
		"password":              auth.Account.Secret,
		"security":              defaultString(r.URL.Query().Get("security"), "any"),
		"ignore-cert":           defaultString(r.URL.Query().Get("ignore_cert"), "true"),
		"recording-path":        s.cfg.Proxy.RDP.RecordingDir(),
		"recording-name":        recordingName,
		"create-recording-path": "true",
	}
	return cfg
}

// finishSession 结束会话：先存储录制文件获取路径，再调用后端 API 标记 session 结束。
func (s *Server) finishSession(ctx context.Context, sessionID int64, recordingName string) error {
	recordingPath, err := s.storeRecording(ctx, recordingName)
	if err != nil {
		recordingPath = "" // 录制存储失败时仍尝试结束 session，但不传路径
	}
	finishErr := s.api.FinishSession(context.Background(), sessionID, recordingPath)
	if err != nil {
		return err // 录制错误优先级高于 finish 错误
	}
	return finishErr
}

// storeRecording 查找本地录制文件并上传至持久化存储。
func (s *Server) storeRecording(ctx context.Context, recordingName string) (string, error) {
	// 通过三层查找策略定位录制文件
	path, err := findRecordingFile(s.cfg.Proxy.RDP.RecordingDir(), recordingName)
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	return s.storage.Put(ctx, "rdp-"+recordingName, file, info.Size())
}

// findRecordingFile 在录制目录中查找指定名称的录制文件，使用三层回退策略：
// 1. 精确匹配 recordingName（无扩展名）
// 2. 追加 .guac 后缀精确匹配
// 3. 使用 glob 模式匹配 recordingName* 前缀的第一个文件
func findRecordingFile(dir, recordingName string) (string, error) {
	// 第1层：精确匹配无扩展名
	// 第2层：精确匹配 .guac 后缀
	candidates := []string{
		filepath.Join(dir, recordingName),
		filepath.Join(dir, recordingName+".guac"),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	// 第3层：glob 模式前缀匹配
	matches, err := filepath.Glob(filepath.Join(dir, recordingName+"*"))
	if err != nil {
		return "", err
	}
	for _, match := range matches {
		info, err := os.Stat(match)
		if err == nil && !info.IsDir() {
			return match, nil
		}
	}
	return "", os.ErrNotExist
}

// sessionTunnel 封装 guac 隧道，管理会话生命周期：关闭时通过 sync.Once 保证只执行一次 finish+release 链。
type sessionTunnel struct {
	guac.Tunnel                                              // 嵌入 guac 隧道接口
	release       func()                                     // 限流器释放回调
	finish        func(context.Context, int64, string) error // session 结束回调
	sessionID     int64                                      // 后端会话 ID
	recordingName string                                     // 录制文件名称
	once          sync.Once                                  // 保证 Close 逻辑只执行一次
}

// Close 通过 sync.Once 确保只关闭一次隧道，然后依次执行 session 结束和限流释放。
func (t *sessionTunnel) Close() error {
	var closeErr error
	t.once.Do(func() {
		closeErr = t.Tunnel.Close()
		// finish+release 链：先结束 session（上传录制），再释放连接槽位
		_ = t.finish(context.Background(), t.sessionID, t.recordingName)
		t.release()
	})
	return closeErr
}
