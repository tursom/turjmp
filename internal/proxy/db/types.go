// Package dbproxy 实现数据库协议代理和 Web 数据库终端功能。
// 支持 MySQL 协议代理（接收客户端 MySQL 连接，通过 API 验证 token 后转发到目标数据库）
// 以及基于 WebSocket + usql 的 Web 数据库终端。
package dbproxy

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"
)

// targetConfig 描述目标数据库的连接配置，由后端 API 在 token 验证时返回。
type targetConfig struct {
	Address  string `json:"address"`  // 目标数据库地址（IP 或主机名）
	Port     int    `json:"port"`     // 目标数据库端口，为 0 时使用协议默认端口
	Protocol string `json:"protocol"` // 数据库协议：mysql / postgres / postgresql
}

// targetAccount 描述目标数据库的认证凭据，由后端 API 返回。
type targetAccount struct {
	Username   string `json:"username"`    // 数据库用户名
	Secret     string `json:"secret"`      // 数据库密码
	SecretType string `json:"secret_type"` // 凭据类型（如 "password"）
	DBName     string `json:"db_name"`     // 默认数据库名
}

// authResult 是 token 验证成功后返回的完整授权信息，
// 包含目标数据库的连接配置、认证凭据以及用户/资产/账号标识。
type authResult struct {
	Target    targetConfig  // 目标数据库配置
	Account   targetAccount // 目标数据库账号
	UserID    int64         // 操作者用户 ID
	AssetID   int64         // 资产 ID
	AccountID int64         // 数据库账号 ID
}

// sessionInfo 描述一个代理会话的元信息，用于创建/完成会话的 API 调用。
type sessionInfo struct {
	UserID        int64  // 用户 ID
	AssetID       int64  // 资产 ID
	AccountID     int64  // 数据库账号 ID
	Protocol      string // 数据库协议
	Type          string // 会话类型（db_proxy / db_terminal）
	ConnectMethod string // 连接方式（mysql_client / web_db）
	RemoteAddr    string // 客户端远程地址
	SessionID     int64  // 会话 ID（由 API 创建后返回）
}

// apiClient 定义与后端 JumpServer API 通信的接口。
// 所有方法都接受 context.Context 以支持超时和取消。
type apiClient interface {
	// VerifyConnectionToken 验证客户端提交的连接 token，返回授权信息。
	VerifyConnectionToken(ctx context.Context, token, remoteAddr string) (authResult, error)
	// CreateSession 在审计系统中创建代理会话记录。
	CreateSession(ctx context.Context, session sessionInfo) (sessionInfo, error)
	// FinishSession 标记会话已结束。
	FinishSession(ctx context.Context, sessionID int64) error
	// Audit 写入审计日志（SQL 审计）。
	Audit(ctx context.Context, userID int64, action, resource, remoteAddr, detail string) error
	// GetSetting 读取配置项（如连接数限制等）。
	GetSetting(ctx context.Context, key string) (string, error)
}

// limiter 是一个基于带缓冲 channel 的并发连接数限制器（信号量模式）。
// 当 channel 满时，acquire 返回 false 表示拒绝新连接。
type limiter struct {
	ch chan struct{} // 缓冲 channel，容量即为最大并发数
}

// newLimiter 创建一个新的并发连接数限制器。
// n 为最大并发连接数，若 n <= 0 则默认设为 1。
func newLimiter(n int) *limiter {
	if n <= 0 {
		n = 1
	}
	return &limiter{ch: make(chan struct{}, n)}
}

// acquire 尝试获取一个连接槽位。成功返回 true，容量已满返回 false。
func (l *limiter) acquire() bool {
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// release 释放一个连接槽位。
func (l *limiter) release() {
	select {
	case <-l.ch:
	default:
	}
}

// extractConnectionToken 从用户名或密码中提取连接 token。
// 支持四种格式，按以下优先级检查：
//  1. 用户名#token — 原生客户端格式，# 分隔符后提取 token（最高优先级）
//  2. 密码#token — token 嵌入在密码字段中
//  3. 密码原值 — 整个密码作为 token（兼容旧客户端）
//  4. 用户名原值 — 仅当密码为空时回退
//
// 设计要点：用户名#token 优先级最高，确保原生 SSH 客户端
// （mysql、psql 等）通过登录用户名传递 token 时不会被普通密码覆盖。
func extractConnectionToken(username, password string) string {
	username = normalizeTokenCandidate(username)
	password = normalizeTokenCandidate(password)
	for _, candidate := range []string{username, password} {
		if candidate == "" {
			continue
		}
		// 检测 username#token 格式，提取 # 后的部分作为 token
		if idx := strings.LastIndex(candidate, "#"); idx >= 0 && idx < len(candidate)-1 {
			return strings.TrimSpace(candidate[idx+1:])
		}
	}
	if password != "" {
		return password
	}
	if username != "" {
		return username
	}
	return ""
}

// normalizeTokenCandidate 清理 token 候选值中的空白字符和 null 字节。
// SSH 客户端或连接字符串可能携带多余的空白符或 \x00 字节，
// 提前清理可避免 API 验证时的匹配失败。
func normalizeTokenCandidate(candidate string) string {
	candidate = strings.Trim(strings.TrimSpace(candidate), "\x00")
	return strings.TrimSpace(candidate)
}

// parseSettingString 从后端 API 返回的原始设置值中解析字符串。
// 设置值可能是裸字符串或 JSON 编码的字符串（如 `"value"`），
// 本函数尝试 JSON 反序列化，失败则去除首尾引号作为回退。
// 若解析结果为空，返回 fallback。
func parseSettingString(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var out string
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		if out == "" {
			return fallback
		}
		return out
	}
	return strings.Trim(raw, `"`)
}

// parseSettingInt 从后端 API 返回的原始设置值中解析整数。
// 先尝试 JSON 反序列化，失败则尝试 strconv 解析（去除首尾引号后）。
// 若所有解析失败，返回 fallback。
func parseSettingInt(raw string, fallback int64) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var n int64
	if err := json.Unmarshal([]byte(raw), &n); err == nil {
		return n
	}
	if parsed, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64); err == nil {
		return parsed
	}
	return fallback
}

// safeRemoteAddr 安全地将 net.Addr 转为字符串，防止 nil panic。
func safeRemoteAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// protocolDefaultPort 根据数据库协议名返回默认端口。
// MySQL 默认 3306，PostgreSQL 默认 5432，其他返回 0。
func protocolDefaultPort(protocol string) int {
	switch strings.ToLower(protocol) {
	case "mysql":
		return 3306
	case "postgres", "postgresql":
		return 5432
	default:
		return 0
	}
}

// targetPort 获取目标数据库的实际连接端口。
// 优先使用配置中的端口，若为 0 则回退到协议默认端口。
func targetPort(target targetConfig) int {
	if target.Port > 0 {
		return target.Port
	}
	if port := protocolDefaultPort(target.Protocol); port > 0 {
		return port
	}
	return target.Port
}

// sqlAuditDetail 是 SQL 审计日志的详细信息结构，会被序列化为 JSON。
type sqlAuditDetail struct {
	SessionID    int64  `json:"session_id"`      // 会话 ID
	Protocol     string `json:"protocol"`        // 数据库协议
	SQL          string `json:"sql"`             // 执行的 SQL 语句
	DurationMS   int64  `json:"duration_ms"`     // 执行耗时（毫秒）
	RowsAffected int64  `json:"rows_affected"`   // 影响行数
	Error        string `json:"error,omitempty"` // 错误信息（无错误时省略）
}

// newSQLAuditDetail 构造一条 SQL 审计详情并序列化为 JSON 字符串。
func newSQLAuditDetail(sessionID int64, protocol, query string, duration time.Duration, rowsAffected int64, err error) string {
	detail := sqlAuditDetail{
		SessionID:    sessionID,
		Protocol:     protocol,
		SQL:          query,
		DurationMS:   duration.Milliseconds(),
		RowsAffected: rowsAffected,
	}
	if err != nil {
		detail.Error = err.Error()
	}
	raw, marshalErr := json.Marshal(detail)
	if marshalErr != nil {
		return `{"error":"marshal audit detail failed"}`
	}
	return string(raw)
}
