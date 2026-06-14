// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责连接令牌的签发、验证、权限校验、凭据解密，以及代理请求的授权检查等核心业务流程的编排与验证。
package service

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// TokenService 连接令牌服务，封装一次性（或可重用）连接令牌的签发与验证流程。签发时校验用户对目标资产和账户的 connect 权限，验证时解密凭据并构建代理连接目标信息。
type TokenService struct {
	store *repository.Store
	box   *crypto.SecretBox
	cfg   config.ProxyAuthConfig
}

// IssueTokenInput 签发连接令牌的输入参数，包含目标资产和账户的 ID、协议类型（ssh/rdp/mysql 等）、连接方式（web_cli 等）、是否可重用以及连接选项 JSON。
type IssueTokenInput struct {
	AssetID        int64  `json:"asset_id"`
	AccountID      int64  `json:"account_id"`
	Protocol       string `json:"protocol"`
	ConnectMethod  string `json:"connect_method"`
	IsReusable     bool   `json:"is_reusable"`
	ConnectOptions string `json:"connect_options"`
}

// VerifyTokenResult 令牌验证成功后返回的完整结果，包含令牌信息、操作用户、目标资产、解密后的账户凭据（密码/密钥）以及代理连接目标信息。
type VerifyTokenResult struct {
	Token   domain.ConnectionToken `json:"token"`
	User    domain.User            `json:"user"`
	Asset   domain.Asset           `json:"asset"`
	Account map[string]any         `json:"account"`
	// Target 连接目标信息，包含资产地址、协议端口和协议类型，供代理组件建立连接使用
	Target VerifyTokenTarget `json:"target"`
}

// VerifyTokenOptions controls proxy-side token verification.
// ExpectedProtocol rejects protocol-mismatched tokens before a one-time token is consumed.
// Consume=false is used by WebSocket handlers for preflight checks before handing the
// token to a protocol proxy that will perform the real consume step.
type VerifyTokenOptions struct {
	ExpectedProtocol string
	Consume          bool
}

// VerifyTokenTarget 连接目标信息，描述验证通过后代理应该连接到哪里
type VerifyTokenTarget struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// NewTokenService 创建 TokenService 实例，注入存储层、加密模块和代理认证配置。
func NewTokenService(store *repository.Store, box *crypto.SecretBox, cfg config.ProxyAuthConfig) *TokenService {
	return &TokenService{store: store, box: box, cfg: cfg}
}

// Issue 签发连接令牌。流程：设置默认连接方式（web_cli）和默认协议（ssh）→ 检查用户是否拥有目标资产和账户的 "connect" 权限 → 若无权限则返回 domain.ErrForbidden → 设置默认连接选项为 "{}" → 生成 UUID 作为令牌值 → 设置 5 分钟过期时间 → 创建并持久化令牌记录。
func (s *TokenService) Issue(userID int64, input IssueTokenInput) (domain.ConnectionToken, error) {
	input.Protocol = canonicalConnectionProtocol(input.Protocol)
	if input.ConnectMethod == "" {
		input.ConnectMethod = "web_cli"
	}
	asset, err := s.store.GetAsset(input.AssetID)
	if err != nil {
		return domain.ConnectionToken{}, err
	}
	account, err := s.store.GetAssetAccount(input.AssetID, input.AccountID)
	if err != nil {
		return domain.ConnectionToken{}, err
	}
	if !asset.IsActive || !account.IsActive {
		return domain.ConnectionToken{}, domain.ErrForbidden
	}
	ok, err := s.store.HasAssetPermission(userID, input.AssetID, input.AccountID, "connect")
	if err != nil {
		return domain.ConnectionToken{}, err
	}
	if !ok {
		return domain.ConnectionToken{}, domain.ErrForbidden
	}
	options := input.ConnectOptions
	if options == "" {
		options = "{}"
	}
	token := domain.ConnectionToken{
		Value:          uuid.NewString(),
		UserID:         userID,
		AssetID:        input.AssetID,
		AccountID:      input.AccountID,
		Protocol:       input.Protocol,
		ConnectMethod:  input.ConnectMethod,
		IsReusable:     input.IsReusable,
		ConnectOptions: options,
		ExpiresAt:      time.Now().UTC().Add(5 * time.Minute),
	}
	return token, s.store.CreateConnectionToken(&token)
}

// Verify 验证连接令牌并返回连接所需的所有信息。流程：调用 AuthorizeProxy 验证代理请求的合法性（密钥匹配 + IP 白名单）→ 从数据库查找令牌 → 检查令牌是否已过期，或非可重用令牌是否已被使用 → 查找操作用户、目标资产和账户 → 查询资产对应协议的端口号（SSH 协议默认 22 端口，其他协议未配置端口则报错）→ 使用 SecretBox 解密账户凭据（Secret）和凭据短语（Passphrase）→ 若非可重用令牌则标记为已使用 → 组装 VerifyTokenResult 并返回。
func (s *TokenService) Verify(value, proxySecret, remoteIP string) (VerifyTokenResult, error) {
	return s.VerifyWithOptions(value, proxySecret, remoteIP, VerifyTokenOptions{Consume: true})
}

func (s *TokenService) VerifyWithOptions(value, proxySecret, remoteIP string, opts VerifyTokenOptions) (VerifyTokenResult, error) {
	if !s.AuthorizeProxy(proxySecret, remoteIP) {
		return VerifyTokenResult{}, domain.ErrUnauthorized
	}
	token, err := s.store.GetConnectionToken(value)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if time.Now().UTC().After(token.ExpiresAt) || token.UsedAt != nil {
		return VerifyTokenResult{}, domain.ErrUnauthorized
	}
	expectedProtocol := canonicalExpectedProtocol(opts.ExpectedProtocol)
	if expectedProtocol != "" && canonicalConnectionProtocol(token.Protocol) != expectedProtocol {
		return VerifyTokenResult{}, domain.ErrForbidden
	}
	user, err := s.store.GetUser(token.UserID)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if !user.IsActive {
		return VerifyTokenResult{}, domain.ErrUnauthorized
	}
	asset, err := s.store.GetAsset(token.AssetID)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	account, err := s.store.GetAccount(token.AccountID)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if account.AssetID != asset.ID || !asset.IsActive || !account.IsActive {
		return VerifyTokenResult{}, domain.ErrForbidden
	}
	ok, err := s.store.HasAssetPermission(token.UserID, token.AssetID, token.AccountID, "connect")
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if !ok {
		return VerifyTokenResult{}, domain.ErrForbidden
	}
	// 查询资产对应协议的端口号，若配置了平台协议则使用配置值
	// 若为 SSH 协议且未查询到端口配置，则默认使用 22 端口
	// 其他协议若未配置端口则返回错误
	port, err := s.store.GetAssetProtocolPort(token.AssetID, token.Protocol)
	if err != nil {
		if token.Protocol == "ssh" {
			port = 22
		} else {
			return VerifyTokenResult{}, err
		}
	}
	secret, err := s.box.DecryptString(account.Secret)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	passphrase, err := s.box.DecryptString(account.Passphrase)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if opts.Consume && !token.IsReusable {
		token, err = s.store.ConsumeConnectionToken(token.Value)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return VerifyTokenResult{}, domain.ErrUnauthorized
			}
			return VerifyTokenResult{}, err
		}
	}
	return VerifyTokenResult{
		Token: token,
		User:  user,
		Asset: asset,
		// Target 包含代理建立连接所需的完整目标信息：资产地址、解析后的端口、协议类型
		Target: VerifyTokenTarget{
			Address:  asset.Address,
			Port:     port,
			Protocol: token.Protocol,
		},
		Account: map[string]any{
			"id":            account.ID,
			"username":      account.Username,
			"secret":        secret,
			"secret_type":   account.SecretType,
			"ssh_key_type":  account.SSHKeyType,
			"passphrase":    passphrase,
			"su_enabled":    account.SUEnabled,
			"su_method":     account.SUMethod,
			"su_account_id": account.SUAccountID,
			"db_name":       account.DBName,
		},
	}, nil
}

func canonicalExpectedProtocol(protocol string) string {
	if strings.TrimSpace(protocol) == "" {
		return ""
	}
	return canonicalConnectionProtocol(protocol)
}

func canonicalConnectionProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "":
		return "ssh"
	case "postgresql":
		return "postgres"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// AuthorizeProxy 验证代理请求的合法性
// 同时校验代理密钥（X-Proxy-Auth）是否匹配配置的共享密钥，以及客户端 IP 是否在白名单内
// 返回 true 表示请求来自受信任的代理组件
func (s *TokenService) AuthorizeProxy(proxySecret, remoteIP string) bool {
	return proxySecret != "" && proxySecret == s.cfg.Secret && s.allowedIP(remoteIP)
}

// allowedIP 检查给定的客户端 IP 是否在代理白名单中。支持精确 IP 匹配和 CIDR 网段匹配。若白名单为空则允许所有 IP。
func (s *TokenService) allowedIP(remoteIP string) bool {
	if len(s.cfg.AllowedIPs) == 0 {
		return true
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		host, _, err := net.SplitHostPort(remoteIP)
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	for _, allowed := range s.cfg.AllowedIPs {
		if allowed == remoteIP {
			return true
		}
		if ip != nil {
			if cidrIP, network, err := net.ParseCIDR(allowed); err == nil {
				if network.Contains(ip) || cidrIP.Equal(ip) {
					return true
				}
				continue
			}
			if ip.Equal(net.ParseIP(allowed)) {
				return true
			}
		}
	}
	return false
}
