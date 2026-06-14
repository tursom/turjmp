package rdpproxy

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

// APIClient talks to the Turjmp backend API using proxy authentication.
type APIClient struct {
	baseURL string
	secret  string
	http    *http.Client
}

// NewAPIClient creates a backend API client for proxy-only endpoints.
func NewAPIClient(cfg config.Config) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(cfg.Proxy.APIBaseURL, "/"),
		secret:  cfg.ProxyAuth.Secret,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// VerifyConnectionToken validates a browser-supplied connection token.
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
		} `json:"account"`
	}
	// 构造 POST 请求：提交 token 和 remote_addr 到验证端点
	if err := c.post(ctx, "/api/v1/authentication/super-connection-tokens/verify/", map[string]any{
		"token":             token,
		"remote_addr":       remoteAddr,
		"expected_protocol": "rdp",
		"consume":           true,
	}, &out); err != nil {
		return authResult{}, err
	}
	// RDP 协议端口为空时，回退到默认端口 3389
	if out.Target.Port == 0 && isRDPProtocol(out.Target.Protocol) {
		out.Target.Port = 3389
	}
	// 将 API 返回的嵌套响应展平为内部 authResult 结构
	return authResult{
		Target: out.Target,
		Account: targetAccount{
			Username:   out.Account.Username,
			Secret:     out.Account.Secret,
			SecretType: out.Account.SecretType,
		},
		UserID:    out.Token.UserID,
		AssetID:   out.Token.AssetID,
		AccountID: out.Token.AccountID,
	}, nil
}

// CreateSession creates an audited RDP session record.
func (c *APIClient) CreateSession(ctx context.Context, session sessionInfo) (sessionInfo, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.post(ctx, "/api/v1/proxy/sessions", map[string]any{
		// 将 session 字段一一映射为 API 请求体，type 和 login_from 使用默认值兜底
		"user_id":        session.UserID,
		"asset_id":       session.AssetID,
		"account_id":     session.AccountID,
		"protocol":       session.Protocol,
		"type":           defaultString(session.Type, "rdp"),
		"login_from":     defaultString(session.ConnectMethod, "web_rdp"),
		"remote_addr":    session.RemoteAddr,
		"recording_path": session.RecordingPath,
	}, &out)
	if err != nil {
		return sessionInfo{}, err
	}
	// 将服务端返回的 session ID 回填到本地对象
	session.SessionID = out.ID
	return session, nil
}

// FinishSession marks an RDP session complete and stores its recording path.
func (c *APIClient) FinishSession(ctx context.Context, sessionID int64, recordingPath string) error {
	// 使用 PATCH 请求标记 is_finished=true 并回写录像路径
	return c.patch(ctx, fmt.Sprintf("/api/v1/proxy/sessions/%d", sessionID), map[string]any{
		"is_finished":    true,
		"recording_path": recordingPath,
	}, nil)
}

// GetSetting fetches a backend setting through the proxy-auth endpoint.
func (c *APIClient) GetSetting(ctx context.Context, key string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	if err := c.get(ctx, "/api/v1/proxy/settings/"+url.PathEscape(key), &out); err != nil {
		return "", err
	}
	return out.Value, nil
}

func (c *APIClient) get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, nil, dst)
}

func (c *APIClient) post(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPost, path, body, dst)
}

func (c *APIClient) patch(ctx context.Context, path string, body any, dst any) error {
	return c.do(ctx, http.MethodPatch, path, body, dst)
}

func (c *APIClient) do(ctx context.Context, method, path string, body any, dst any) error {
	// 1. 序列化请求体为 JSON 字节流
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
	// 2. 构造 HTTP 请求并挂载 context
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	// 3. 添加代理认证头和 Content-Type
	req.Header.Set("X-Proxy-Auth", c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// 4. 执行 HTTP 请求
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 5. 204 No Content 直接返回成功（不需要解析响应体）
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	// 6. 解析统一响应信封 { data: ..., error: { code, message } }
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
	// 7. HTTP 状态码非 2xx 时提取错误信息
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error != nil {
			return fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return fmt.Errorf("代理 API 返回状态码 %d", resp.StatusCode)
	}
	if dst == nil {
		return nil
	}
	// 8. 将信封中的 data 字段反序列化到目标对象
	return json.Unmarshal(envelope.Data, dst)
}

// defaultString 空值兜底：value 为空字符串时返回 fallback 作为默认值
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
