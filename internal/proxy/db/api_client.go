// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
// 本文件实现后端 JumpServer API 的 HTTP 客户端，提供 token 验证、会话管理和审计日志功能。
package dbproxy

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

// APIClient 是后端 JumpServer API 的 HTTP 客户端。
// 封装了所有代理所需的 API 调用（token 验证、会话 CRUD、审计日志、配置查询），
// 自动处理认证头（X-Proxy-Auth）、JSON 序列化和响应解析。
type APIClient struct {
	baseURL string       // API 基础 URL（去掉尾部 /）
	secret  string       // 代理认证密钥（X-Proxy-Auth 头）
	http    *http.Client // HTTP 客户端（30s 超时）
}

// NewAPIClient 创建一个新的 API 客户端实例。
// 从配置中读取 API 基础 URL 和认证密钥。
func NewAPIClient(cfg config.Config) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(cfg.Proxy.APIBaseURL, "/"),
		secret:  cfg.ProxyAuth.Secret,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// VerifyConnectionToken 向后端 API 验证连接 token 的有效性。
// 请求：POST /api/v1/authentication/super-connection-tokens/verify/
// 参数：token（连接 token）和 remote_addr（客户端 IP）
// 返回：包含目标数据库配置、账号凭据和用户/资产/账号 ID 的授权结果。
func (c *APIClient) VerifyConnectionToken(ctx context.Context, token, remoteAddr string) (authResult, error) {
	var out struct {
		Token struct {
			UserID    int64 `json:"user_id"`
			AssetID   int64 `json:"asset_id"`
			AccountID int64 `json:"account_id"`
		} `json:"token"`
		Target  targetConfig `json:"target"`
		Account struct {
			Username   string `json:"username"`
			Secret     string `json:"secret"`
			SecretType string `json:"secret_type"`
			DBName     string `json:"db_name"`
		} `json:"account"`
	}
	if err := c.post(ctx, "/api/v1/authentication/super-connection-tokens/verify/", map[string]string{
		"token":       token,
		"remote_addr": remoteAddr,
	}, &out); err != nil {
		return authResult{}, err
	}
	// 若目标端口未指定，使用协议默认端口
	if out.Target.Port == 0 {
		out.Target.Port = protocolDefaultPort(out.Target.Protocol)
	}
	return authResult{
		Target: out.Target,
		Account: targetAccount{
			Username:   out.Account.Username,
			Secret:     out.Account.Secret,
			SecretType: out.Account.SecretType,
			DBName:     out.Account.DBName,
		},
		UserID:    out.Token.UserID,
		AssetID:   out.Token.AssetID,
		AccountID: out.Token.AccountID,
	}, nil
}

// CreateSession 在审计系统中创建一条代理会话记录。
// 请求：POST /api/v1/proxy/sessions
// 返回的 sessionInfo 中包含了 API 分配的会话 ID。
func (c *APIClient) CreateSession(ctx context.Context, session sessionInfo) (sessionInfo, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.post(ctx, "/api/v1/proxy/sessions", map[string]any{
		"user_id":     session.UserID,
		"asset_id":    session.AssetID,
		"account_id":  session.AccountID,
		"protocol":    session.Protocol,
		"type":        defaultString(session.Type, "db_proxy"),
		"login_from":  defaultString(session.ConnectMethod, "db_client"),
		"remote_addr": session.RemoteAddr,
	}, &out)
	if err != nil {
		return sessionInfo{}, err
	}
	session.SessionID = out.ID
	return session, nil
}

// FinishSession 标记会话已结束。
// 请求：PATCH /api/v1/proxy/sessions/{id}
// 设置 is_finished = true。
func (c *APIClient) FinishSession(ctx context.Context, sessionID int64) error {
	return c.patch(ctx, fmt.Sprintf("/api/v1/proxy/sessions/%d", sessionID), map[string]any{
		"is_finished": true,
	}, nil)
}

// Audit 写入一条审计日志。
// 请求：POST /api/v1/proxy/audit-logs
// userID 为 0 时，user_id 字段为 null（表示系统操作）。
func (c *APIClient) Audit(ctx context.Context, userID int64, action, resource, remoteAddr, detail string) error {
	var userIDPtr *int64
	if userID > 0 {
		userIDPtr = &userID
	}
	return c.post(ctx, "/api/v1/proxy/audit-logs", map[string]any{
		"user_id":     userIDPtr,
		"action":      action,
		"resource":    resource,
		"remote_addr": remoteAddr,
		"detail":      detail,
	}, nil)
}

// GetSetting 从后端 API 读取配置项的值。
// 请求：GET /api/v1/proxy/settings/{key}
// key 参数会被 URL 路径转义以支持包含特殊字符的键名。
func (c *APIClient) GetSetting(ctx context.Context, key string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	if err := c.get(ctx, "/api/v1/proxy/settings/"+url.PathEscape(key), &out); err != nil {
		return "", err
	}
	return out.Value, nil
}

// get 执行 HTTP GET 请求。
func (c *APIClient) get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

// post 执行 HTTP POST 请求。
func (c *APIClient) post(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPost, path, body, dst)
}

// patch 执行 HTTP PATCH 请求。
func (c *APIClient) patch(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPatch, path, body, dst)
}

// do 是 HTTP 请求的统一执行方法。
// 流程：
//  1. 序列化请求体为 JSON
//  2. 构建 HTTP 请求（添加 X-Proxy-Auth 认证头和 Content-Type）
//  3. 发送请求并读取响应
//  4. 解析 JSON 响应信封：{"data": ..., "error": {"code":"...", "message":"..."}}
//  5. 检查 HTTP 状态码，非 2xx 返回错误
//  6. 若 dst 非 nil，将 data 字段反序列化到 dst
func (c *APIClient) do(ctx context.Context, method, path string, body any, dst any) error {
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
	req.Header.Set("X-Proxy-Auth", c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	// 解析标准响应信封
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

// defaultString 返回 value 如果非空，否则返回 fallback。
// 用于为可选字段提供默认值。
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
