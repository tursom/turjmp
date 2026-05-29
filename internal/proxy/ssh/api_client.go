// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件包含与主 API 服务器通信的 HTTP 客户端实现。
package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tursom/turjmp/internal/config"
)

// APIClient 是与主 API 服务器通信的 HTTP 客户端。
// 负责令牌验证、会话管理、审计日志、命令过滤规则获取和设置查询。
type APIClient struct {
	baseURL string       // API 服务器的基础 URL
	secret  string       // 代理认证密钥（X-Proxy-Auth 头部）
	http    *http.Client // HTTP 客户端，带 30 秒超时
}

// NewAPIClient 创建一个新的 API 客户端实例。
// 参数 cfg 包含 API 服务器的 URL 和认证密钥。
// 返回初始化后的 API 客户端。
func NewAPIClient(cfg config.Config) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(cfg.Proxy.APIBaseURL, "/"),
		secret:  cfg.ProxyAuth.Secret,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// VerifyConnectionToken 向 API 服务器验证用户的连接令牌。
// 验证通过后返回目标资产的连接配置和账户认证信息。
// 参数 ctx 是上下文，token 是用户提供的连接令牌，remoteAddr 是用户远程地址。
// 返回认证结果，如果验证失败则返回错误。默认端口为 22。
func (c *APIClient) VerifyConnectionToken(ctx context.Context, token, remoteAddr string) (targetAuthResult, error) {
	var out struct {
		Token struct {
			UserID        int64  `json:"user_id"`
			AssetID       int64  `json:"asset_id"`
			AccountID     int64  `json:"account_id"`
			Protocol      string `json:"protocol"`
			ConnectMethod string `json:"connect_method"`
		} `json:"token"`
		Target  targetConfig `json:"target"`
		Account struct {
			Username    string `json:"username"`
			Secret      string `json:"secret"`
			SecretType  string `json:"secret_type"`
			SSHKeyType  string `json:"ssh_key_type"`
			Passphrase  string `json:"passphrase"`
			SUEnabled   bool   `json:"su_enabled"`
			SUMethod    string `json:"su_method"`
			SUAccountID *int64 `json:"su_account_id"`
			DBName      string `json:"db_name"`
		} `json:"account"`
	}
	if err := c.post(ctx, "/api/v1/authentication/super-connection-tokens/verify/", map[string]string{
		"token":       token,
		"remote_addr": remoteAddr,
	}, &out); err != nil {
		return targetAuthResult{}, err
	}
	// 如果目标端口未指定，默认使用 SSH 标准端口 22
	if out.Target.Port == 0 {
		out.Target.Port = 22
	}
	return targetAuthResult{
		Target: out.Target,
		Account: targetAccount{
			Username:    out.Account.Username,
			Secret:      out.Account.Secret,
			SecretType:  out.Account.SecretType,
			SSHKeyType:  out.Account.SSHKeyType,
			Passphrase:  out.Account.Passphrase,
			SUEnabled:   out.Account.SUEnabled,
			SUMethod:    out.Account.SUMethod,
			SUAccountID: out.Account.SUAccountID,
			DBName:      out.Account.DBName,
		},
		UserID:    out.Token.UserID,
		AssetID:   out.Token.AssetID,
		AccountID: out.Token.AccountID,
	}, nil
}

// CreateSession 在 API 服务器上创建新的会话记录。
// 参数 ctx 是上下文，session 包含会话的元数据信息。
// 返回更新后的会话信息（包含服务器分配的 SessionID），如果创建失败则返回错误。
func (c *APIClient) CreateSession(ctx context.Context, session targetSessionInfo) (targetSessionInfo, error) {
	var out struct {
		ID            int64  `json:"id"`
		UserID        int64  `json:"user_id"`
		AssetID       int64  `json:"asset_id"`
		AccountID     int64  `json:"account_id"`
		Protocol      string `json:"protocol"`
		LoginFrom     string `json:"login_from"`
		RemoteAddr    string `json:"remote_addr"`
		RecordingPath string `json:"recording_path"`
	}
	err := c.post(ctx, "/api/v1/proxy/sessions", map[string]any{
		"user_id":        session.UserID,
		"asset_id":       session.AssetID,
		"account_id":     session.AccountID,
		"protocol":       session.Protocol,
		"type":           defaultString(session.Type, "normal"),
		"login_from":     session.ConnectMethod,
		"remote_addr":    session.RemoteAddr,
		"recording_path": session.RecordingPath,
	}, &out)
	if err != nil {
		return targetSessionInfo{}, err
	}
	session.SessionID = out.ID
	return session, nil
}

// FinishSession 标记会话已完成并记录录像文件路径。
// 参数 ctx 是上下文，sessionID 是会话 ID，recordingPath 是录像文件路径。
// 返回 nil 表示成功，否则返回错误。
func (c *APIClient) FinishSession(ctx context.Context, sessionID int64, recordingPath string) error {
	return c.patch(ctx, fmt.Sprintf("/api/v1/proxy/sessions/%d", sessionID), map[string]any{
		"is_finished":    true,
		"recording_path": recordingPath,
	}, nil)
}

// Audit 向 API 服务器提交审计日志记录。
// 用于记录 SFTP 操作等需要审计的行为。
// 参数 ctx 是上下文，userID 是用户 ID，action 是操作类型，
// resource 是操作的资源路径，remoteAddr 是远程地址，detail 是详细信息。
// 返回 nil 表示成功，否则返回错误。
func (c *APIClient) Audit(ctx context.Context, userID int64, action, resource, remoteAddr, detail string) error {
	return c.post(ctx, "/api/v1/proxy/audit-logs", map[string]any{
		"user_id":     userID,
		"action":      action,
		"resource":    resource,
		"remote_addr": remoteAddr,
		"detail":      detail,
	}, nil)
}

// ListCommandFilterACLs 从 API 服务器获取命令过滤规则列表。
// 参数 ctx 是上下文。
// 返回命令过滤规则切片，如果获取失败则返回错误。
func (c *APIClient) ListCommandFilterACLs(ctx context.Context) ([]commandFilterRule, error) {
	var out []commandFilterRule
	if err := c.get(ctx, "/api/v1/proxy/command-filter-acls", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetSetting 从 API 服务器获取指定 key 的代理设置值。
// 参数 ctx 是上下文，key 是设置的键名。
// 返回设置值字符串，如果获取失败则返回错误。
func (c *APIClient) GetSetting(ctx context.Context, key string) (string, error) {
	var out struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := c.get(ctx, "/api/v1/proxy/settings/"+url.PathEscape(key), &out); err != nil {
		return "", err
	}
	return out.Value, nil
}

// GetHostKeys 从 API 服务器获取 SSH 主机密钥列表。
// 参数 ctx 是上下文。
// 返回私钥字符串列表，如果获取失败则返回错误。
func (c *APIClient) GetHostKeys(ctx context.Context) ([]string, error) {
	var out []struct {
		PrivateKey string `json:"private_key"`
	}
	if err := c.get(ctx, "/api/v1/proxy/ssh/host-keys", &out); err != nil {
		return nil, err
	}
	// 从响应中提取私钥字符串
	keys := make([]string, 0, len(out))
	for _, key := range out {
		keys = append(keys, key.PrivateKey)
	}
	return keys, nil
}

// get 执行 HTTP GET 请求并将响应解析到 dst。
func (c *APIClient) get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

// post 执行 HTTP POST 请求，发送 JSON body 并将响应解析到 dst。
func (c *APIClient) post(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPost, path, body, dst)
}

// patch 执行 HTTP PATCH 请求，发送 JSON body 并将响应解析到 dst。
func (c *APIClient) patch(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPatch, path, body, dst)
}

// do 执行 HTTP 请求的通用方法。
// 处理 JSON 序列化/反序列化、认证头部设置和统一响应格式解析。
// API 响应格式为 { "data": ..., "error": { "code": "...", "message": "..." } }。
// 参数 ctx 是上下文，method 是 HTTP 方法，path 是请求路径，
// body 是请求体（可为 nil），dst 是响应数据反序列化目标（可为 nil）。
// 返回 nil 表示成功，否则返回错误。
func (c *APIClient) do(ctx context.Context, method, path string, body any, dst any) error {
	// 构建请求体
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	// 设置代理认证头部和内容类型
	req.Header.Set("X-Proxy-Auth", c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// HTTP 204 No Content 表示请求成功但无响应体（如 PATCH 更新、审计日志写入等接口），
	// 此时无需解析 JSON 应答，直接返回 nil
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	// 解析统一响应格式
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	// 检查 HTTP 状态码
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error != nil {
			return fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return fmt.Errorf("proxy api returned status %d", resp.StatusCode)
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(envelope.Data, dst)
}

// defaultString 返回 value，如果 value 为空则返回 fallback 默认值。
// 用于为可选字段提供默认值。
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
