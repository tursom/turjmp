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
//  2. 从 URL query 参数中获取连接 token 和数据库协议
//  3. 构建指向本机数据库代理的 usql DSN（URL 格式）
//  4. 数据库代理消费 token、创建审计会话并记录 SQL
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/tursom/turjmp/internal/config"
)

// WebTerminal 是 Web 数据库终端的 HTTP 处理器。
// 它管理一个 WebSocket 端点，将浏览器终端模拟器连接到 usql 子进程，再经本机数据库代理访问目标库。
type WebTerminal struct {
	cfg   config.Config // 全局配置（包含 usql 命令路径、数据库代理监听地址等）
	api   apiClient
	limit *limiter // Web DB 终端并发限制器
}

// NewWebTerminal 创建一个新的 Web 数据库终端处理器。
func NewWebTerminal(cfg config.Config) *WebTerminal {
	return &WebTerminal{
		cfg:   cfg,
		api:   NewAPIClient(cfg),
		limit: newLimiter(cfg.Proxy.DB.ConnectionLimit()),
	}
}

// ServeHTTP 处理 Web 数据库终端的 HTTP 请求（标准 net/http Handler 接口）。
//
// 完整交互流程：
//
//  1. WebSocket 升级     — 从 URL query 中获取 token，接受 WebSocket 连接
//  2. 协议解析           — 从 URL query 中获取 mysql/postgres 协议
//  3. DSN 构建           — 构建连接本机数据库代理的 usql 连接字符串
//  4. 审计委托           — 由数据库代理消费 token、创建会话并审计 SQL
//  5. 启动 usql 子进程   — 使用 exec.CommandContext 启动 usql，再从 PTY 注入连接命令
//  6. PTY 分配           — 通过 pty.StartWithSize 为 usql 分配 80x24 的伪终端
//  7. 双向数据桥接       — 启动 copyPTYOutput（PTY→WS）和 copyWSInput（WS→PTY）两个 goroutine
//  8. 等待并清理         — 等待 PTY 输出 goroutine 结束，终止子进程，关闭 PTY
func (t *WebTerminal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 获取并验证 token
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}
	protocol := normalizeDBProtocol(r.URL.Query().Get("protocol"))
	if protocol == "" {
		http.Error(w, "protocol required", http.StatusBadRequest)
		return
	}
	// 升级 HTTP 连接为 WebSocket
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if t.api != nil {
		if _, err := t.api.PreflightConnectionToken(ctx, token, r.RemoteAddr, protocol); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
			return
		}
	}
	// 2. 构建指向本机数据库代理的 usql DSN，避免 Web 终端直连目标库绕过 SQL 审计。
	dsn, err := buildUSQLProxyDSN(protocol, token, t.cfg.Proxy.DB)
	if err != nil {
		_ = conn.Close(websocket.StatusUnsupportedData, err.Error())
		return
	}
	if t.limit != nil {
		if !t.limit.acquire() {
			_ = conn.Close(websocket.StatusTryAgainLater, "too many db terminal connections")
			return
		}
		defer t.limit.release()
	}

	// 5. 启动 usql 子进程。DSN 不放入 argv，避免数据库凭据暴露在进程参数里。
	cmd := exec.CommandContext(ctx, t.cfg.Proxy.DB.UsqlCommand())
	// 6. 为 usql 分配 PTY（伪终端），初始大小 80x24
	ptyFile, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, fmt.Sprintf("start usql failed: %v", err))
		return
	}
	defer ptyFile.Close()
	// 确保子进程最终被终止
	defer func() { _ = cmd.Process.Kill() }()
	var closeOnce sync.Once
	closeTerminal := func() {
		closeOnce.Do(func() {
			cancel()
			_ = ptyFile.Close()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = conn.Close(websocket.StatusNormalClosure, "")
		})
	}

	if err := sendUSQLConnectCommand(ptyFile, dsn); err != nil {
		_ = conn.Close(websocket.StatusInternalError, fmt.Sprintf("connect usql failed: %v", err))
		return
	}
	scrubber := newTerminalOutputScrubber(dsn, token)

	// 7. 启动 PTY→WebSocket 和 WebSocket→PTY 桥接，任一方向结束都清理整条会话。
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		t.copyPTYOutput(ctx, conn, ptyFile, scrubber)
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		t.copyWSInput(ctx, conn, ptyFile)
	}()
	select {
	case <-inputDone:
	case <-outputDone:
	case <-ctx.Done():
	}
	closeTerminal()
	// 8. 等待桥接 goroutine 退出
	<-outputDone
	<-inputDone
	_ = cmd.Wait()
}

func sendUSQLConnectCommand(terminal *os.File, dsn string) error {
	restore, err := disableTerminalEcho(terminal)
	if err != nil {
		return err
	}
	defer restore()
	_, err = terminal.WriteString("\\connect " + dsn + "\n")
	return err
}

func disableTerminalEcho(terminal *os.File) (func(), error) {
	fd := int(terminal.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	updated := *original
	updated.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &updated); err != nil {
		return nil, err
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, original)
	}, nil
}

const dbSessionFinishPollInterval = 2 * time.Second

func watchDBSessionFinish(ctx context.Context, api apiClient, sessionID int64, closeFn func()) context.CancelFunc {
	watchCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	closeSession := func() {
		once.Do(func() {
			if closeFn != nil {
				closeFn()
			}
		})
	}
	go func() {
		ticker := time.NewTicker(dbSessionFinishPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				session, err := api.GetSession(watchCtx, sessionID)
				if err != nil {
					continue
				}
				if session.IsFinished {
					closeSession()
					return
				}
			}
		}
	}()
	return cancel
}

// copyPTYOutput 从 PTY 读取 usql 的输出并通过 WebSocket 二进制帧发送给浏览器。
// 使用 32KB 缓冲区循环读取，读取到数据后立即发送。
// 当 PTY 关闭（子进程退出）或连接断开时返回。
func (t *WebTerminal) copyPTYOutput(ctx context.Context, conn *websocket.Conn, r io.Reader, scrubber *terminalOutputScrubber) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// 复制数据以避免缓冲区被后续写入覆盖
			data := append([]byte(nil), buf[:n]...)
			if scrubber != nil {
				data = scrubber.Scrub(data, false)
			}
			if len(data) > 0 {
				_ = conn.Write(ctx, websocket.MessageBinary, data)
			}
		}
		if err != nil {
			if scrubber != nil {
				if tail := scrubber.Scrub(nil, true); len(tail) > 0 {
					_ = conn.Write(ctx, websocket.MessageBinary, tail)
				}
			}
			return
		}
	}
}

type terminalOutputScrubber struct {
	replacements []terminalOutputReplacement
	tail         string
	keep         int
}

type terminalOutputReplacement struct {
	value       string
	replacement string
}

func newTerminalOutputScrubber(values ...string) *terminalOutputScrubber {
	seen := make(map[string]struct{})
	var replacements []terminalOutputReplacement
	maxLen := 0
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		replacements = append(replacements, terminalOutputReplacement{
			value:       value,
			replacement: "[redacted]",
		})
		if len(value) > maxLen {
			maxLen = len(value)
		}
	}
	if len(replacements) == 0 {
		return nil
	}
	sort.Slice(replacements, func(i, j int) bool {
		return len(replacements[i].value) > len(replacements[j].value)
	})
	keep := maxLen - 1
	if keep < 0 {
		keep = 0
	}
	return &terminalOutputScrubber{replacements: replacements, keep: keep}
}

func (s *terminalOutputScrubber) Scrub(data []byte, flush bool) []byte {
	if s == nil {
		return data
	}
	combined := s.tail + string(data)
	for _, item := range s.replacements {
		combined = strings.ReplaceAll(combined, item.value, item.replacement)
	}
	if !flush && len(combined) <= s.keep {
		s.tail = combined
		return nil
	}
	emitLen := len(combined)
	if !flush {
		emitLen = len(combined) - s.keep
	}
	emit := combined[:emitLen]
	s.tail = combined[emitLen:]
	return []byte(emit)
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
	guard := newUSQLInputGuard()
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			// 二进制帧：直接写入 PTY（如 Ctrl+C 等控制字符）
			_, _ = terminal.Write(guard.Filter(data))
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
				_, _ = terminal.Write(guard.Filter([]byte(input.Data)))
				continue
			}
			// 回退：作为原始文本写入 PTY
			_, _ = terminal.Write(guard.Filter(data))
		default:
			// 不支持的帧类型
			_ = conn.Close(websocket.StatusUnsupportedData, fmt.Sprintf("unsupported message type %d", typ))
			return
		}
	}
}

type usqlInputGuard struct {
	line strings.Builder
}

func newUSQLInputGuard() *usqlInputGuard {
	return &usqlInputGuard{}
}

func (g *usqlInputGuard) Filter(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, 0, len(data))
	for _, b := range data {
		switch b {
		case '\r', '\n':
			if g.blockCurrentLine() {
				out = append(out, 0x15)
			} else {
				out = append(out, b)
			}
			g.line.Reset()
		case 0x03, 0x15:
			g.line.Reset()
			out = append(out, b)
		case 0x08, 0x7f:
			current := g.line.String()
			if len(current) > 0 {
				g.line.Reset()
				g.line.WriteString(current[:len(current)-1])
			}
			out = append(out, b)
		default:
			g.line.WriteByte(b)
			out = append(out, b)
		}
	}
	return out
}

func (g *usqlInputGuard) blockCurrentLine() bool {
	return strings.HasPrefix(strings.TrimSpace(g.line.String()), `\`)
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
