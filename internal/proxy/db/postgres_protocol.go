// Package dbproxy 提供数据库代理相关的实现。
// 本文件包含 PostgreSQL 有线协议（wire protocol）的工具函数和数据结构，
// 用于代理层的连接管理、取消请求转发、协议识别和协议消息构造。
package dbproxy

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// postgresReadyIdle 表示 PostgreSQL ReadyForQuery 消息中的事务状态"空闲"。
// ReadyForQuery 是服务端在每个事务或语句块完成后发送的消息，
// 其 TxStatus 字段可能为 'I'（空闲/不在事务中）、'T'（事务中）或 'E'（失败事务中）。
const postgresReadyIdle = 'I'

// postgresCancelTarget 存储一个可取消的后端连接的网络地址和身份信息。
// 当代理收到 CancelRequest 时，需要通过 processID+secretKey 定位到原始后端连接。
type postgresCancelTarget struct {
	network   string // 网络类型，如 "tcp"、"unix"
	address   string // 目标地址，格式如 "host:port"
	processID uint32 // PostgreSQL 会话的进程 ID（来自 BackendKeyData 消息）
	secretKey []byte // PostgreSQL 会话的密钥（来自 BackendKeyData 消息）
}

// postgresCancelRegistry 管理所有可取消后端连接的注册表。
// 每个活跃的代理连接在收到服务器的 BackendKeyData 后会注册到该表中，
// 以便后续 CancelRequest 能根据 processID+secretKey 找到对应的后端连接并转发取消请求。
type postgresCancelRegistry struct {
	mu      sync.RWMutex                    // 读写锁，保护并发访问
	entries map[string]postgresCancelTarget // 键为 "processID:hex(secretKey)"，值为目标地址
	timeout time.Duration                    // 取消请求转发的超时时间
}

// newPostgresCancelRegistry 创建一个新的取消请求注册表。
// timeout 指定取消请求转发的网络超时时间。
func newPostgresCancelRegistry(timeout time.Duration) *postgresCancelRegistry {
	return &postgresCancelRegistry{
		entries: make(map[string]postgresCancelTarget),
		timeout: timeout,
	}
}

// add 将一个 PostgreSQL 会话注册到取消表中，返回一个移除函数。
// 返回的 func() 在连接断开或会话结束时调用，从表中删除该条目。
func (r *postgresCancelRegistry) add(target postgresCancelTarget) func() {
	key := postgresCancelKey(target.processID, target.secretKey)
	r.mu.Lock()
	r.entries[key] = target
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.entries, key)
		r.mu.Unlock()
	}
}

// forward 接收一个 CancelRequest 消息，将其转发到对应的后端连接。
// 流程：
//  1. 根据请求中的 processID 和 secretKey 查找注册的后端目标
//  2. 查找失败则返回错误
//  3. 建立到后端地址的 TCP 连接
//  4. 发送 PostgreSQL Cancel 请求的二进制数据包（16+N 字节）
//  5. 等待 1 字节的确认（ack，实际 CancelRequest 不返回任何响应，
//     此处 Read 仅用于等待连接关闭或超时）
func (r *postgresCancelRegistry) forward(ctx context.Context, req *pgproto3.CancelRequest) error {
	key := postgresCancelKey(req.ProcessID, req.SecretKey)
	r.mu.RLock()
	target, ok := r.entries[key]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("PostgreSQL 取消目标未找到")
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 15 * time.Second // 默认15秒超时
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, target.network, target.address)
	if err != nil {
		return err
	}
	defer conn.Close()

	payload := postgresCancelBytes(target.processID, target.secretKey)
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var ack [1]byte
	_, _ = conn.Read(ack[:])
	return nil
}

// postgresCancelKey 构造取消注册表中条目的唯一键。
// 格式: "进程ID:secretKey的十六进制表示"
// 例如: "1234:a1b2c3d4e5f6..."
func postgresCancelKey(processID uint32, secretKey []byte) string {
	return strconv.FormatUint(uint64(processID), 10) + ":" + hex.EncodeToString(secretKey)
}

// postgresStartupToken 从 PostgreSQL 启动消息（StartupMessage）的 user 参数中提取连接 token。
// PostgreSQL 客户端在连接建立时发送 StartupMessage，其中包含 "user"、"database" 等参数。
// 代理层可能在用户名中嵌入认证 token，此函数负责提取 token。
// 如果 msg 为 nil，返回空字符串。
func postgresStartupToken(msg *pgproto3.StartupMessage) string {
	if msg == nil {
		return ""
	}
	return extractConnectionToken(msg.Parameters["user"], "")
}

// isPostgresProtocol 判断传入的协议名是否为 PostgreSQL 协议。
// 支持 "postgres" 和 "postgresql" 两种写法（不区分大小写）。
func isPostgresProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

// sendPostgresError 向客户端发送一个 FATAL 级别的错误消息，并刷新缓冲区。
// 用于代理层需要主动拒绝连接或报告协议级别错误时。
// code: PostgreSQL 错误代码（如 "08006"、"28P01"）
// message: 人类可读的错误描述
func sendPostgresError(backend *pgproto3.Backend, code, message string) error {
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     code,
		Message:  message,
	})
	return backend.Flush()
}

// writePostgresSSLRefusal 向客户端写入 'N' 字节，表示拒绝 SSL/GSS 加密请求。
//
// PostgreSQL 协议的 SSL 协商流程：
//  1. 客户端发送 SSLRequest（格式类似 StartupMessage，但协议版本为 80877103）
//  2. 服务端回复单字节：'S' 表示支持 SSL，'N' 表示拒绝
//  3. 如果是 'N'，客户端收到后继续发送 StartupMessage 进行明文连接
//
// 代理层面不支持加密，因此在收到 SSL/GSS 请求时统一回复 'N' 拒绝。
func writePostgresSSLRefusal(conn net.Conn) error {
	_, err := conn.Write([]byte{'N'})
	return err
}

// parsePostgresRowsAffected 从 CommandComplete 消息的 commandTag 中解析影响的行数。
//
// PostgreSQL CommandComplete 消息的 commandTag 格式示例：
//   - "INSERT 0 1"    → 返回 1
//   - "DELETE 3"      → 返回 3
//   - "UPDATE 5"      → 返回 5
//   - "SELECT 100"    → 返回 100
//   - "CREATE TABLE"  → 返回 -1（无法解析）
//
// 解析方式：从后往前按空格分割，取最后一个能解析为整数的字段。
func parsePostgresRowsAffected(commandTag []byte) int64 {
	fields := strings.Fields(string(commandTag))
	// 从最后一个字段开始向前搜索，找到第一个可解析为整数的字段
	for i := len(fields) - 1; i >= 0; i-- {
		n, err := strconv.ParseInt(fields[i], 10, 64)
		if err == nil {
			return n
		}
	}
	return -1 // 无法解析时返回 -1
}

// postgresError 将 pgproto3.ErrorResponse 转换为 Go error。
// 优先级：Code + Message > Message > 默认字符串 "postgres error"。
// 如果传入 nil，返回 nil。
func postgresError(err *pgproto3.ErrorResponse) error {
	if err == nil {
		return nil
	}
	if err.Code != "" && err.Message != "" {
		return fmt.Errorf("%s: %s", err.Code, err.Message)
	}
	if err.Message != "" {
		return fmt.Errorf("%s", err.Message)
	}
	return fmt.Errorf("PostgreSQL 错误")
}

// postgresCancelBytes 构造 PostgreSQL CancelRequest 的二进制数据包。
//
// PostgreSQL 取消请求的二进制格式（大端序）：
//   - [0:4]   4 字节：消息总长度（含自身，不含 secretKey 时固定为 16）
//   - [4:8]   4 字节：CancelRequest 魔数 80877102（协议常量）
//   - [8:12]  4 字节：目标进程 ID
//   - [12:]   剩余字节：secretKey（来自 BackendKeyData 消息）
//
// 注意：CancelRequest 是唯一不使用标准 PostgreSQL 消息格式（类型字节+长度+payload）的消息，
// 它采用固定格式的二进制包，客户端在收到服务端响应前就关闭连接。
func postgresCancelBytes(processID uint32, secretKey []byte) []byte {
	buf := make([]byte, 12+len(secretKey))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(buf)))    // 消息总长度（大端序）
	binary.BigEndian.PutUint32(buf[4:8], 80877102)            // CancelRequest 魔数（大端序）
	binary.BigEndian.PutUint32(buf[8:12], processID)          // 目标进程 ID（大端序）
	copy(buf[12:], secretKey)                                 // 复制密钥
	return buf
}
