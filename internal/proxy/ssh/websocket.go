// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件包含 WebSocket 终端的实现，允许通过浏览器 WebSocket 协议访问 SSH 终端。
package sshproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coder/websocket"
	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/recorder"
)

// WebTerminal 是 WebSocket 终端的核心结构体。
// 它处理浏览器通过 WebSocket 发起的 SSH 终端连接请求，
// 桥接 WebSocket 和 SSH 之间的数据流。
type WebTerminal struct {
	cfg    config.Config // 代理配置
	api    *APIClient    // API 客户端，用于令牌验证和会话管理
	dialer *sshDialer    // SSH 拨号器，管理到目标资产的连接
}

// NewWebTerminal 创建一个新的 WebSocket 终端处理器。
// 参数 cfg 包含代理的所有配置信息。
// 返回初始化后的 WebTerminal 实例。
func NewWebTerminal(cfg config.Config) *WebTerminal {
	api := NewAPIClient(cfg)
	return &WebTerminal{cfg: cfg, api: api, dialer: newSSHDialer(cfg.Proxy.SSH, api)}
}

// ServeHTTP 实现 http.Handler 接口，处理 WebSocket 连接请求。
// 完整的处理流程：
// 1. 从 URL 查询参数获取连接令牌
// 2. 升级 HTTP 连接为 WebSocket
// 3. 验证连接令牌
// 4. 获取连接槽位（连接数限制）
// 5. 拨号连接目标资产
// 6. 创建会话记录
// 7. 创建录像写入器（asciicast v2 格式）
// 8. 在目标上启动交互式 Shell
// 9. 启动 goroutine 桥接 WebSocket 和 SSH 的数据流
func (t *WebTerminal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 从 URL 查询参数获取连接令牌
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}
	// 升级 HTTP 连接为 WebSocket
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx := r.Context()
	// 验证连接令牌
	auth, err := t.api.VerifyConnectionToken(ctx, token, r.RemoteAddr)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	// 获取连接槽位
	if !t.dialer.acquire() {
		_ = conn.Close(websocket.StatusTryAgainLater, "too many connections")
		return
	}
	defer t.dialer.release()
	// 拨号连接目标资产
	client, err := t.dialer.dialSSH(ctx, auth.Target, auth.Account)
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	defer client.Close()
	// 在 API 服务器上创建会话记录（连接方式标记为 web_cli）
	session, err := t.api.CreateSession(ctx, targetSessionInfo{
		UserID:        auth.UserID,
		AssetID:       auth.AssetID,
		AccountID:     auth.AccountID,
		Protocol:      "ssh",
		Type:          "normal",
		ConnectMethod: "web_cli",
		RemoteAddr:    r.RemoteAddr,
	})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	// 获取录像存储路径并创建 asciicast v2 格式的录像写入器
	recBase := "./recordings"
	if raw, err := t.api.GetSetting(ctx, "recording.local.path"); err == nil {
		recBase = parseSettingString(raw, recBase)
	}
	recPath := filepath.Join(recBase, strconv.FormatInt(session.SessionID, 10)+".cast")
	cast, _ := recorder.NewCastWriter(recPath, 80, 24)
	defer func() {
		if cast != nil {
			_ = cast.Close()
		}
		// 会话结束后通知 API 标记完成
		_ = t.api.FinishSession(context.Background(), session.SessionID, recPath)
	}()

	// 在目标资产上创建 SSH session
	sshSession, err := client.NewSession()
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	defer sshSession.Close()
	stopWatch := watchSessionFinish(ctx, t.api, session.SessionID, func() {
		_ = sshSession.Close()
		_ = client.Close()
		_ = conn.Close(websocket.StatusNormalClosure, "session force finished")
	})
	defer stopWatch()
	// 请求伪终端（使用 xterm-256color，初始大小 80x24）
	if err := sshSession.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	// 获取输入输出管道
	stdin, _ := sshSession.StdinPipe()
	stdout, _ := sshSession.StdoutPipe()
	stderr, _ := sshSession.StderrPipe()
	// 在目标上启动交互式 Shell
	if err := sshSession.Shell(); err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	// 启动三个 goroutine 桥接数据流：
	// 1. SSH stdout -> 录像 -> WebSocket
	go t.copySSHOutput(ctx, conn, stdout, cast)
	// 2. SSH stderr -> 录像 -> WebSocket
	go t.copySSHOutput(ctx, conn, stderr, cast)
	// 3. WebSocket 用户输入 -> SSH stdin
	go t.copyWSInput(ctx, conn, stdin, sshSession, cast)
	// 等待远程 Shell 结束
	_ = sshSession.Wait()
}

// copySSHOutput 将 SSH 会话的输出复制到 WebSocket 连接。
// 同时将数据写入录像文件（asciicast v2 格式）。
// 参数 ctx 是上下文，conn 是 WebSocket 连接，r 是 SSH 输出读取器，cast 是录像写入器。
func (t *WebTerminal) copySSHOutput(ctx context.Context, conn *websocket.Conn, r io.Reader, cast *recorder.CastWriter) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// 深拷贝数据以避免共享缓冲区
			data := append([]byte(nil), buf[:n]...)
			// 写入录像文件
			if cast != nil {
				_ = cast.WriteOutput(data)
			}
			// 通过 WebSocket 发送二进制数据
			_ = conn.Write(ctx, websocket.MessageBinary, data)
		}
		if err != nil {
			return
		}
	}
}

// copyWSInput 将 WebSocket 的输入数据转发到 SSH 会话的标准输入。
// 支持两种消息类型：
// - Binary 消息：直接写入 SSH stdin
// - Text 消息：JSON 格式，支持 resize（窗口大小调整）和普通文本输入
// 参数 ctx 是上下文，conn 是 WebSocket 连接，stdin 是 SSH 标准输入，
// session 是 SSH 会话（用于窗口调整），cast 是录像写入器。
func (t *WebTerminal) copyWSInput(ctx context.Context, conn *websocket.Conn, stdin io.Writer, session *gossh.Session, cast *recorder.CastWriter) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			// 二进制数据直接写入 SSH stdin
			_, _ = stdin.Write(data)
		case websocket.MessageText:
			// 解析 JSON 消息
			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Rows int    `json:"rows"`
				Cols int    `json:"cols"`
			}
			if err := json.Unmarshal(data, &msg); err == nil && msg.Type == "resize" {
				// 处理窗口大小调整请求
				if msg.Rows > 0 && msg.Cols > 0 {
					_ = session.WindowChange(msg.Rows, msg.Cols)
					if cast != nil {
						_ = cast.WriteResize(msg.Cols, msg.Rows)
					}
				}
				continue
			}
			if msg.Data != "" {
				// Text 消息中的 data 字段作为输入
				_, _ = stdin.Write([]byte(msg.Data))
				continue
			}
			// 降级处理：原始文本数据作为输入
			_, _ = stdin.Write(data)
		default:
			// 不支持的消息类型，关闭连接
			_ = conn.Close(websocket.StatusUnsupportedData, fmt.Sprintf("unsupported message type %d", typ))
			return
		}
	}
}

// keepWebsocketTime 保留对 time.Time 包的引用，防止 go mod tidy 移除依赖。
func keepWebsocketTime(time.Time) {}
