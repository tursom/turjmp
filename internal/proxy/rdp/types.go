// Package rdpproxy implements the RDP Web proxy backed by Apache guacd.
package rdpproxy

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// targetConfig describes the RDP target returned by the backend API.
type targetConfig struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// targetAccount describes the target account credentials returned by the backend API.
type targetAccount struct {
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
}

// authResult is the connection-token authorization result needed by RDP sessions.
type authResult struct {
	Target    targetConfig
	Account   targetAccount
	UserID    int64
	AssetID   int64
	AccountID int64
}

// sessionInfo describes a proxy session tracked by the backend API.
type sessionInfo struct {
	UserID        int64
	AssetID       int64
	AccountID     int64
	Protocol      string
	Type          string
	ConnectMethod string
	RemoteAddr    string
	RecordingPath string
	SessionID     int64
}

// nativeSessionInfo describes a native RDP MITM session started by FreeRDP.
type nativeSessionInfo struct {
	sessionInfo
	Target  targetConfig
	Account targetAccount
}

// apiClient is the subset of backend API calls needed by the RDP proxy.
type apiClient interface {
	VerifyConnectionToken(ctx context.Context, token, remoteAddr string) (authResult, error)
	ResolveNativeRDP(ctx context.Context, routeUsername, password, remoteAddr string) (authResult, error)
	StartNativeRDPSession(ctx context.Context, routeUsername, password, remoteAddr string) (nativeSessionInfo, error)
	FinishNativeRDPSession(ctx context.Context, sessionID int64, reason string) error
	FinishActiveNativeRDPSessions(ctx context.Context, reason string) error
	CreateSession(ctx context.Context, session sessionInfo) (sessionInfo, error)
	FinishSession(ctx context.Context, sessionID int64, recordingPath string) error
	GetSetting(ctx context.Context, key string) (string, error)
}

// limiter is a small semaphore used to cap concurrent RDP sessions.
type limiter struct {
	ch chan struct{}
}

func newLimiter(n int) *limiter {
	// 容量保护：传入无效容量时至少保留 1 个并发位，防止死锁
	if n <= 0 {
		n = 1
	}
	// 创建带缓冲的 channel 作为信号量：容量 n 代表最大并发会话数
	return &limiter{ch: make(chan struct{}, n)}
}

func (l *limiter) acquire() bool {
	// 非阻塞获取信号量：channel 未满则写入成功并返回 true，满则立即返回 false
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *limiter) release() {
	// 非阻塞释放信号量：从 channel 取出一个元素以释放一个并发位，channel 为空时直接返回
	select {
	case <-l.ch:
	default:
	}
}

func safeRemoteAddr(addr net.Addr) string {
	// nil 保护：当 addr 为 nil 时返回空字符串，避免空指针解引用
	if addr == nil {
		return ""
	}
	return addr.String()
}

func isRDPProtocol(protocol string) bool {
	// 不区分大小写比较，识别 RDP 协议请求
	return strings.EqualFold(protocol, "rdp")
}

func rdpTargetPort(target targetConfig) int {
	// 优先使用 API 返回的端口号，未指定时回退到 RDP 默认端口 3389
	if target.Port > 0 {
		return target.Port
	}
	return 3389
}

func parseSettingString(raw, fallback string) string {
	// 第 1 层：去除首尾空白
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var out string
	// 第 2 层：尝试 JSON 反序列化（处理带引号的 JSON 字符串）
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		if out == "" {
			return fallback
		}
		return out
	}
	// 第 3 层：JSON 解析失败时，直接剥离两端双引号
	return strings.Trim(raw, `"`)
}

func parsePositiveInt(raw string, fallback int) int {
	// 第 1 层：去除首尾空白
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var n int
	// 第 2 层：尝试 JSON 整数反序列化，成功且为正数时返回
	if err := json.Unmarshal([]byte(raw), &n); err == nil && n > 0 {
		return n
	}
	// 第 3 层：JSON 解析失败时，剥离引号后尝试 Atoi 转换，成功且为正数时返回
	if parsed, err := strconv.Atoi(strings.Trim(raw, `"`)); err == nil && parsed > 0 {
		return parsed
	}
	// 所有解析失败，返回默认值
	return fallback
}
