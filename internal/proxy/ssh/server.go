// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该包负责接收用户的 SSH 连接请求，通过 API 服务器验证连接令牌后进行身份认证，
// 然后建立到目标资产的 SSH 隧道，并桥接用户与目标之间的数据流。
// 支持普通 Shell 会话、SFTP 文件传输、端口转发以及 WebSocket 终端。
package sshproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/recorder"
)

// Server 是 SSH 代理服务器的主结构体。
// 它封装了 gliderlabs SSH 服务器、API 客户端、网络监听器和生命周期控制。
type Server struct {
	cfg      config.Config      // 代理配置信息
	api      *APIClient         // 与主 API 服务器通信的客户端
	ssh      *gliderssh.Server  // 底层 gliderlabs SSH 服务器实例
	listener net.Listener       // TCP 网络监听器
	stopMu   sync.Mutex         // 保护 stopFn 的互斥锁
	stopFn   context.CancelFunc // 取消函数，用于停止服务器
}

// NewServer 创建一个新的 SSH 代理服务器实例。
// 它会初始化 API 客户端、SSH 拨号器，并带重试机制获取主机密钥。
// 参数 cfg 包含代理的所有配置信息。
// 返回初始化后的 Server 实例，如果获取主机密钥失败则返回错误。
func NewServer(cfg config.Config) (*Server, error) {
	api := NewAPIClient(cfg)
	dialer := newSSHDialer(cfg.Proxy.SSH, api)
	// 带重试机制从 API 服务器获取主机密钥
	keys, err := getHostKeysWithRetry(context.Background(), api)
	if err != nil {
		return nil, err
	}
	// 将原始密钥字符串解析为 SSH 签名器
	signers := make([]gliderssh.Signer, 0, len(keys))
	for _, raw := range keys {
		signer, err := gossh.ParsePrivateKey([]byte(raw))
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}
	// 配置 gliderlabs SSH 服务器
	sshServer := &gliderssh.Server{
		Addr:            cfg.Proxy.SSH.Addr,
		Handler:         handleSession(cfg, api, dialer),
		HostSigners:     signers,
		PasswordHandler: passwordHandler(api),
		// 允许本地端口转发（只要目标不为空）
		LocalPortForwardingCallback: func(ctx gliderssh.Context, destinationHost string, destinationPort uint32) bool {
			return destinationHost != ""
		},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"direct-tcpip": directTCPIPHandler(cfg, api, dialer),
		},
		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": sftpSubsystemHandler(cfg, api, dialer),
		},
		IdleTimeout: cfg.Proxy.SSH.IdleTimeout(),
	}
	return &Server{cfg: cfg, api: api, ssh: sshServer}, nil
}

// getHostKeysWithRetry 带重试机制从 API 服务器获取主机密钥列表。
// 最多重试 20 次，每次间隔 100ms，支持上下文取消。
// 参数 ctx 用于传递上下文以实现超时和取消控制。
// 返回主机密钥字符串列表，如果所有重试都失败则返回最后一次错误。
func getHostKeysWithRetry(ctx context.Context, api *APIClient) ([]string, error) {
	var lastErr error
	for i := 0; i < 20; i++ {
		keys, err := api.GetHostKeys(ctx)
		if err == nil {
			return keys, nil
		}
		lastErr = err
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

// Start 启动 SSH 代理服务器。
// 创建 TCP 监听器，在后台 goroutine 中运行 SSH 服务，
// 并通过 context 实现生命周期管理。
// 参数 ctx 用于传递上下文，可通过取消 ctx 来优雅停止服务器。
// 返回 nil 表示正常关闭，否则返回错误。
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Proxy.SSH.Addr)
	if err != nil {
		return err
	}
	s.listener = ln
	// 创建可取消的上下文用于控制服务器运行
	runCtx, cancel := context.WithCancel(ctx)
	s.stopMu.Lock()
	s.stopFn = cancel
	s.stopMu.Unlock()
	errCh := make(chan error, 1)
	// 在后台 goroutine 中运行 SSH 服务
	go func() {
		errCh <- s.ssh.Serve(ln)
	}()
	// 等待上下文取消或服务返回错误
	select {
	case <-runCtx.Done():
		return s.ssh.Close()
	case err := <-errCh:
		if err == gliderssh.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Stop 优雅停止 SSH 代理服务器。
// 调用取消函数并关闭网络监听器。
func (s *Server) Stop() {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if s.stopFn != nil {
		s.stopFn()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

// HandleSignals 注册操作系统信号处理器。
// 当收到 SIGINT、SIGTERM 或 os.Interrupt 信号时，调用 stop 函数。
// 参数 stop 是停止服务器的回调函数。
func HandleSignals(stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		stop()
	}()
}

// passwordHandler 创建 SSH 密码认证处理器。
// 用户通过连接令牌（而非真实密码）进行认证。
// 该函数验证令牌后，将目标资产信息、账户信息和用户/资产 ID 存入 SSH 会话上下文。
// 参数 api 是用于验证令牌的 API 客户端。
// 返回 gliderlabs 兼容的密码验证函数。
func passwordHandler(api *APIClient) gliderssh.PasswordHandler {
	return func(ctx gliderssh.Context, password string) bool {
		remote := ""
		if addr := ctx.RemoteAddr(); addr != nil {
			remote = addr.String()
		}
		// 1. 从 gliderlabs 上下文获取 SSH 用户名
		username := ctx.User()
		// 2. 默认使用密码作为令牌（向后兼容旧客户端）
		token := password
		// 3. 尝试提取 username#token 格式 —— 若提取成功则使用提取出的令牌
		if extracted := extractConnectionToken(username, password); extracted != "" {
			token = extracted
		}
		// 4. 通过 API 验证提取出的连接令牌
		auth, err := api.VerifyConnectionToken(ctx, token, remote)
		if err != nil {
			return false
		}
		// 5. 将认证结果存入 SSH 会话上下文，供下游处理器使用
		ctx.SetValue("ssh_target", auth.Target)
		ctx.SetValue("ssh_account", auth.Account)
		ctx.SetValue("ssh_auth_user_id", auth.UserID)
		ctx.SetValue("ssh_auth_asset_id", auth.AssetID)
		ctx.SetValue("ssh_auth_account_id", auth.AccountID)
		return true
	}
}

// handleSession 创建处理 SSH 主会话的处理器。
// 该函数实现完整的 SSH 会话代理流程：
// 1. 从上下文中取出认证信息
// 2. 通过连接限制检查
// 3. 拨号连接目标资产
// 4. 在 API 服务器上创建会话记录
// 5. 设置 asciicast v2 格式的录像
// 6. 在目标上启动 shell 或执行命令
// 7. 桥接输入输出流并应用命令过滤
// 参数 cfg 是代理配置，api 是 API 客户端，dialer 是 SSH 拨号器。
func handleSession(cfg config.Config, api *APIClient, dialer *sshDialer) gliderssh.Handler {
	return func(sess gliderssh.Session) {
		// 从会话上下文取出认证信息
		authTarget, ok := sess.Context().Value("ssh_target").(targetConfig)
		if !ok {
			_, _ = io.WriteString(sess, "missing auth target\n")
			_ = sess.Exit(1)
			return
		}
		authAccount, ok := sess.Context().Value("ssh_account").(targetAccount)
		if !ok {
			_, _ = io.WriteString(sess, "missing auth account\n")
			_ = sess.Exit(1)
			return
		}
		userID := sess.Context().Value("ssh_auth_user_id").(int64)
		assetID := sess.Context().Value("ssh_auth_asset_id").(int64)
		accountID := sess.Context().Value("ssh_auth_account_id").(int64)
		// 检查连接数限制
		if !dialer.acquire() {
			_, _ = io.WriteString(sess, "too many connections\n")
			_ = sess.Exit(1)
			return
		}
		defer dialer.release()

		// 拨号连接到目标资产
		client, err := dialer.dialSSH(sess.Context(), authTarget, authAccount)
		if err != nil {
			_, _ = io.WriteString(sess, fmt.Sprintf("connect target failed: %v\n", err))
			_ = sess.Exit(1)
			return
		}
		defer client.Close()

		// 在 API 服务器上创建会话记录
		session, err := api.CreateSession(sess.Context(), targetSessionInfo{
			UserID:        userID,
			AssetID:       assetID,
			AccountID:     accountID,
			Protocol:      "ssh",
			Type:          "normal",
			ConnectMethod: "ssh_client",
			RemoteAddr:    safeRemoteAddr(sess.RemoteAddr()),
		})
		if err != nil {
			_, _ = io.WriteString(sess, fmt.Sprintf("create session failed: %v\n", err))
			_ = sess.Exit(1)
			return
		}

		// 获取录像存储路径并创建 asciicast v2 格式的录像写入器
		recBase := "./recordings"
		if raw, err := api.GetSetting(sess.Context(), "recording.local.path"); err == nil {
			recBase = parseSettingString(raw, recBase)
		}
		recPath := filepath.Join(recBase, strconv.FormatInt(session.SessionID, 10)+".cast")
		width, height := 80, 24
		if ptyReq, _, ok := sess.Pty(); ok {
			width, height = ptyReq.Window.Width, ptyReq.Window.Height
		}
		cast, _ := recorder.NewCastWriter(recPath, width, height)
		defer func() {
			if cast != nil {
				_ = cast.Close()
			}
			// 会话结束后通知 API 标记完成
			_ = api.FinishSession(sess.Context(), session.SessionID, recPath)
		}()

		// 在目标资产上创建远程 session
		remoteSession, err := client.NewSession()
		if err != nil {
			_, _ = io.WriteString(sess, fmt.Sprintf("target session failed: %v\n", err))
			_ = sess.Exit(1)
			return
		}
		defer remoteSession.Close()
		stopWatch := watchSessionFinish(sess.Context(), api, session.SessionID, func() {
			_ = remoteSession.Close()
			_ = client.Close()
			_ = sess.Close()
		})
		defer stopWatch()

		// 如果用户请求了 PTY，在目标上分配伪终端
		ptyReq, winCh, hasPty := sess.Pty()
		if hasPty {
			if err := remoteSession.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, gossh.TerminalModes{}); err != nil {
				_, _ = io.WriteString(sess, fmt.Sprintf("pty failed: %v\n", err))
				_ = sess.Exit(1)
				return
			}
			// 后台 goroutine 监听窗口大小变化并同步到目标会话和录像
			go func() {
				for win := range winCh {
					_ = remoteSession.WindowChange(win.Height, win.Width)
					if cast != nil {
						_ = cast.WriteResize(win.Width, win.Height)
					}
				}
			}()
		}

		// 获取目标会话的标准输入输出管道
		stdin, _ := remoteSession.StdinPipe()
		stdout, _ := remoteSession.StdoutPipe()
		stderr, _ := remoteSession.StderrPipe()
		// 加载命令过滤规则，通过过滤读写器处理用户输入
		filter, _ := loadCommandFilter(sess.Context(), api)
		// 启动三个 goroutine 桥接数据流：
		// 1. 用户输入 -> 过滤 -> 目标 stdin
		go func() { _, _ = io.Copy(stdin, newFilteringReader(sess, sess, filter)) }()
		// 2. 目标 stdout -> 录像写入器 -> 用户终端
		output := recorder.NewRecordingWriter(sess, cast)
		errOutput := recorder.NewRecordingWriter(sess.Stderr(), cast)
		go func() { _, _ = io.Copy(output, stdout) }()
		// 3. 目标 stderr -> 录像写入器 -> 用户终端
		go func() { _, _ = io.Copy(errOutput, stderr) }()
		// 如果有原始命令则执行命令，否则启动交互式 shell
		if raw := sess.RawCommand(); raw != "" {
			auditSSHCommand(sess.Context(), api, userID, session.SessionID, safeRemoteAddr(sess.RemoteAddr()), raw)
			if err := remoteSession.Start(raw); err != nil {
				_, _ = io.WriteString(sess, fmt.Sprintf("exec failed: %v\n", err))
				_ = sess.Exit(1)
				return
			}
		} else if err := remoteSession.Shell(); err != nil {
			_, _ = io.WriteString(sess, fmt.Sprintf("shell failed: %v\n", err))
			_ = sess.Exit(1)
			return
		}
		// 等待远程命令/Shell 完成
		_ = remoteSession.Wait()
		_ = sess.Exit(0)
	}
}

func auditSSHCommand(ctx context.Context, api apiClient, userID, sessionID int64, remoteAddr, command string) {
	detail, err := json.Marshal(map[string]any{
		"session_id": sessionID,
		"command":    command,
	})
	if err != nil {
		return
	}
	_ = api.Audit(ctx, userID, "ssh.command", "ssh", remoteAddr, string(detail))
}

// directTCPIPHandler 创建处理 SSH 端口转发（direct-tcpip）的通道处理器。
// 该处理器在用户和目标资产之间建立 TCP 隧道，用于端口转发场景。
// 同样需要进行连接限制检查、会话记录和审计。
// 参数 cfg 是代理配置，api 是 API 客户端，dialer 是 SSH 拨号器。
func directTCPIPHandler(cfg config.Config, api *APIClient, dialer *sshDialer) gliderssh.ChannelHandler {
	return func(srv *gliderssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx gliderssh.Context) {
		// 检查连接数限制
		if !dialer.acquire() {
			newChan.Reject(gossh.ResourceShortage, "too many connections")
			return
		}
		defer dialer.release()
		// 从上下文获取认证后的目标信息
		authTarget, ok := ctx.Value("ssh_target").(targetConfig)
		if !ok {
			newChan.Reject(gossh.Prohibited, "missing token target")
			return
		}
		// 解析端口转发的目标地址信息
		var target localForwardChannelData
		if err := gossh.Unmarshal(newChan.ExtraData(), &target); err != nil {
			newChan.Reject(gossh.ConnectionFailed, err.Error())
			return
		}
		// 直接 TCP 拨号到目标资产
		addr := net.JoinHostPort(authTarget.Address, strconv.Itoa(authTarget.Port))
		var netDialer net.Dialer
		targetConn, err := netDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			newChan.Reject(gossh.ConnectionFailed, err.Error())
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			_ = targetConn.Close()
			return
		}
		go gossh.DiscardRequests(reqs)
		// 获取会话关联的认证信息
		userID, _ := ctx.Value("ssh_auth_user_id").(int64)
		assetID, _ := ctx.Value("ssh_auth_asset_id").(int64)
		accountID, _ := ctx.Value("ssh_auth_account_id").(int64)
		// 创建端口转发类型的会话记录
		session, err := api.CreateSession(ctx, targetSessionInfo{
			UserID:        userID,
			AssetID:       assetID,
			AccountID:     accountID,
			Protocol:      "ssh",
			Type:          "tunnel",
			ConnectMethod: "ssh_client",
			RemoteAddr:    safeRemoteAddr(conn.RemoteAddr()),
		})
		if err == nil {
			stopWatch := watchSessionFinish(ctx, api, session.SessionID, func() {
				_ = ch.Close()
				_ = targetConn.Close()
			})
			defer func() {
				stopWatch()
				_ = api.FinishSession(context.Background(), session.SessionID, "")
			}()
		}
		// 启动双向数据复制 goroutine，桥接用户和目标之间的 TCP 流
		go func() {
			defer ch.Close()
			defer targetConn.Close()
			_, _ = io.Copy(ch, targetConn)
		}()
		go func() {
			defer ch.Close()
			defer targetConn.Close()
			_, _ = io.Copy(targetConn, ch)
		}()
		_ = target
		_ = cfg
		_ = api
	}
}

// localForwardChannelData 表示 SSH 本地端口转发的通道数据。
// 包含目标地址、目标端口、来源地址和来源端口。
type localForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// sftpSubsystemHandler 创建处理 SFTP 子系统的处理器。
// 当用户请求 SFTP 子系统时，该处理器会：
// 1. 认证并连接目标资产
// 2. 创建 SFTP 客户端
// 3. 解析 SFTP 策略（文件大小限制、路径黑名单）
// 4. 创建会话记录
// 5. 通过代理处理器转发 SFTP 请求
// 参数 cfg 是代理配置，api 是 API 客户端，dialer 是 SSH 拨号器。
func sftpSubsystemHandler(cfg config.Config, api *APIClient, dialer *sshDialer) gliderssh.SubsystemHandler {
	return func(sess gliderssh.Session) {
		// 从上下文取出认证信息
		authTarget, ok := sess.Context().Value("ssh_target").(targetConfig)
		if !ok {
			_, _ = io.WriteString(sess, "missing auth target\n")
			return
		}
		authAccount := sess.Context().Value("ssh_account").(targetAccount)
		userID, _ := sess.Context().Value("ssh_auth_user_id").(int64)
		assetID, _ := sess.Context().Value("ssh_auth_asset_id").(int64)
		accountID, _ := sess.Context().Value("ssh_auth_account_id").(int64)
		// 拨号连接目标资产
		client, err := dialer.dialSSH(sess.Context(), authTarget, authAccount)
		if err != nil {
			_, _ = io.WriteString(sess, err.Error())
			return
		}
		defer client.Close()
		// 基于 SSH 连接创建 SFTP 客户端
		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			_, _ = io.WriteString(sess, err.Error())
			return
		}
		defer sftpClient.Close()
		// 获取 SFTP 策略配置（文件大小限制和路径黑名单）
		maxValue, _ := api.GetSetting(sess.Context(), "sftp.max_file_size")
		denyValue, _ := api.GetSetting(sess.Context(), "sftp.deny_paths")
		// 创建 SFTP 类型的会话记录
		session, err := api.CreateSession(sess.Context(), targetSessionInfo{
			UserID:        userID,
			AssetID:       assetID,
			AccountID:     accountID,
			Protocol:      "ssh",
			Type:          "sftp",
			ConnectMethod: "ssh_client",
			RemoteAddr:    safeRemoteAddr(sess.RemoteAddr()),
		})
		// 创建远程 SFTP 代理处理器，包含策略和审计回调
		handlers := &remoteSFTPHandlers{
			client: sftpClient,
			policy: parseSFTPPolicy(maxValue, denyValue),
			audit: func(action, resource, detail string) {
				_ = api.Audit(context.Background(), userID, "sftp."+action, resource, safeRemoteAddr(sess.RemoteAddr()), detail)
			},
		}
		// 启动 SFTP 请求服务器，注册各种文件操作处理器
		server := sftp.NewRequestServer(sess, sftp.Handlers{
			FileGet:  handlers,
			FilePut:  handlers,
			FileCmd:  handlers,
			FileList: handlers,
		})
		defer server.Close()
		if err == nil {
			stopWatch := watchSessionFinish(sess.Context(), api, session.SessionID, func() {
				_ = server.Close()
				_ = sftpClient.Close()
				_ = client.Close()
				_ = sess.Close()
			})
			defer func() {
				stopWatch()
				_ = api.FinishSession(context.Background(), session.SessionID, "")
			}()
		}
		_ = cfg
		_ = server.Serve()
	}
}

// safeRemoteAddr 安全地获取远程地址的字符串表示。
// 如果 addr 为 nil 则返回空字符串，避免空指针解引用。
// 参数 addr 是网络地址接口。
// 返回地址的字符串表示。
func safeRemoteAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
