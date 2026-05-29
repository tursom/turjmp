// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
//
// 本文件实现基于 Web 的数据库终端功能。
//
// 架构概览（usql 子进程模型）：
//
//	浏览器 ←→ WebSocket (wss://) ←→ Go 代理 ←→ PTY  ←→ usql 子进程 ←→ 目标数据库
//	                                                         |            (MySQL/PG)
//	                                              ┌──────────┘
//	                                         PTY 分配 (creack/pty)
//	                                              ├─ copyPTYOutput: PTY stdout → WebSocket Binary Frames
//	                                              └─ copyWSInput:   WebSocket Frames → PTY stdin
//
// 流程：
//  1. 浏览器通过 WebSocket 升级连接到 Go HTTP 服务器
//  2. 从 URL query 参数中获取连接 token，通过 API 验证
//  3. 根据授权的目标数据库信息构建 usql 兼容的 DSN（URL 格式）
//  4. 创建审计会话记录
//  5. 使用 exec.CommandContext 启动 usql 子进程（usql 是一个用 Go 编写的通用 SQL 客户端）
//  6. 通过 creack/pty 库为 usql 分配伪终端（PTY），实现完整的终端交互体验
//  7. 启动两个 goroutine 桥接 PTY 和 WebSocket：
//     ─ copyPTYOutput: 从 PTY 读取 usql 输出，通过 WebSocket 发送给浏览器
//     ─ copyWSInput:   从 WebSocket 读取浏览器输入，写入 PTY
//  8. 支持终端窗口大小调整（resize）：浏览器发送 JSON 消息 {"type":"resize","rows":N,"cols":M}
//  9. 连接断开后，清理子进程并标记会话结束
package dbproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/tursom/turjmp/internal/config"
)

// WebTerminal 是 Web 数据库终端的 HTTP 处理器。
// 它管理一个 WebSocket 端点，将浏览器终端模拟器连接到目标数据库的 usql 子进程。
type WebTerminal struct {
	cfg config.Config // 全局配置（包含 usql 命令路径等）
	api *APIClient    // 后端 API 客户端（token 验证、会话管理）
}

// NewWebTerminal 创建一个新的 Web 数据库终端处理器。
func NewWebTerminal(cfg config.Config) *WebTerminal {
	return &WebTerminal{cfg: cfg, api: NewAPIClient(cfg)}
}

// ServeHTTP 处理 Web 数据库终端的 HTTP 请求（标准 net/http Handler 接口）。
//
// 完整交互流程：
//
//  1. WebSocket 升级     — 从 URL query 中获取 token，接受 WebSocket 连接
//  2. Token 验证         — 调用后端 API 验证连接 token
//  3. DSN 构建           — 根据验证结果构建 usql 兼容的连接字符串
//  4. 会话创建           — 在审计系统中创建 db_terminal 类型的会话记录
//  5. 启动 usql 子进程   — 使用 exec.CommandContext 启动 usql，传入 DSN 作为参数
//  6. PTY 分配           — 通过 pty.StartWithSize 为 usql 分配 80x24 的伪终端
//  7. 双向数据桥接       — 启动 copyPTYOutput（PTY→WS）和 copyWSInput（WS→PTY）两个 goroutine
//  8. 等待并清理         — 等待 PTY 输出 goroutine 结束，终止子进程，关闭 PTY
//  9. 标记会话结束       — defer 调用 FinishSession
func (t *WebTerminal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 获取并验证 token
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
	// 2. 验证连接 token，获取目标数据库授权信息
	auth, err := t.api.VerifyConnectionToken(ctx, token, r.RemoteAddr)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	// 3. 构建 usql DSN（URL 格式，如 mysql://user:pass@host:port/db）
	dsn, err := buildUSQLDSN(auth)
	if err != nil {
		_ = conn.Close(websocket.StatusUnsupportedData, err.Error())
		return
	}
	// 4. 创建审计会话记录
	session, err := t.api.CreateSession(ctx, sessionInfo{
		UserID:        auth.UserID,
		AssetID:       auth.AssetID,
		AccountID:     auth.AccountID,
		Protocol:      auth.Target.Protocol,
		Type:          "db_terminal",
		ConnectMethod: "web_db",
		RemoteAddr:    r.RemoteAddr,
	})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	// 连接关闭时标记会话结束（使用 Background context 确保即使请求 context 取消也能完成）
	defer func() {
		_ = t.api.FinishSession(context.Background(), session.SessionID)
	}()

	// 5. 启动 usql 子进程，传入 DSN 作为命令行参数
	cmd := exec.CommandContext(ctx, t.cfg.Proxy.DB.UsqlCommand(), dsn)
	// 6. 为 usql 分配 PTY（伪终端），初始大小 80x24
	ptyFile, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, fmt.Sprintf("start usql failed: %v", err))
		return
	}
	defer ptyFile.Close()
	// 确保子进程最终被终止
	defer func() { _ = cmd.Process.Kill() }()

	// 7. 启动 PTY→WebSocket 输出桥接（在后台 goroutine 中运行）
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.copyPTYOutput(ctx, conn, ptyFile)
	}()
	// WebSocket→PTY 输入桥接（在当前 goroutine 中运行，阻塞直到连接断开）
	t.copyWSInput(ctx, conn, ptyFile)
	// 8. 等待输出 goroutine 结束
	<-done
	_ = cmd.Wait()
}

// copyPTYOutput 从 PTY 读取 usql 的输出并通过 WebSocket 二进制帧发送给浏览器。
// 使用 32KB 缓冲区循环读取，读取到数据后立即发送。
// 当 PTY 关闭（子进程退出）或连接断开时返回。
func (t *WebTerminal) copyPTYOutput(ctx context.Context, conn *websocket.Conn, r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// 复制数据以避免缓冲区被后续写入覆盖
			data := append([]byte(nil), buf[:n]...)
			_ = conn.Write(ctx, websocket.MessageBinary, data)
		}
		if err != nil {
			return
		}
	}
}

// copyWSInput 从 WebSocket 读取浏览器发送的数据并写入 PTY。
//
// 支持三种 WebSocket 消息类型：
//   - MessageBinary  — 原始二进制数据，直接写入 PTY
//   - MessageText    — 先尝试解析为终端 resize 消息，再尝试 JSON 输入，最后作为原始文本
//   - 其他           — 不支持的帧类型，关闭连接
//
// resize 消息格式（JSON）：{"type": "resize", "rows": N, "cols": M}
// 用于在浏览器终端窗口大小变化时同步调整 PTY 尺寸。
func (t *WebTerminal) copyWSInput(ctx context.Context, conn *websocket.Conn, terminal *os.File) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			// 二进制帧：直接写入 PTY（如 Ctrl+C 等控制字符）
			_, _ = terminal.Write(data)
		case websocket.MessageText:
			// 文本帧：尝试多种解析模式
			msg, ok := parseResizeMessage(data)
			if ok {
				// 终端窗口大小调整
				_ = pty.Setsize(terminal, &pty.Winsize{Rows: uint16(msg.Rows), Cols: uint16(msg.Cols)})
				continue
			}
			// 尝试 JSON 格式输入 {"data": "..."}
			var input struct {
				Data string `json:"data"`
			}
			if err := json.Unmarshal(data, &input); err == nil && input.Data != "" {
				_, _ = terminal.Write([]byte(input.Data))
				continue
			}
			// 回退：作为原始文本写入 PTY
			_, _ = terminal.Write(data)
		default:
			// 不支持的帧类型
			_ = conn.Close(websocket.StatusUnsupportedData, fmt.Sprintf("unsupported message type %d", typ))
			return
		}
	}
}

// resizeMessage 是浏览器终端发送的窗口大小调整消息。
// JSON 格式：{"type": "resize", "rows": <行数>, "cols": <列数>}
type resizeMessage struct {
	Type string `json:"type"` // 固定为 "resize"
	Rows int    `json:"rows"` // 终端行数
	Cols int    `json:"cols"` // 终端列数
}

// parseResizeMessage 尝试将 WebSocket 文本帧解析为 resize 消息。
// 验证 type 必须为 "resize" 且 rows 和 cols 必须为正整数。
func parseResizeMessage(data []byte) (resizeMessage, bool) {
	var msg resizeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return resizeMessage{}, false
	}
	if msg.Type != "resize" || msg.Rows <= 0 || msg.Cols <= 0 {
		return resizeMessage{}, false
	}
	return msg, true
}
