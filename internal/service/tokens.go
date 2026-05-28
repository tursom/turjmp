package service

import (
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type TokenService struct {
	store *repository.Store
	box   *crypto.SecretBox
	cfg   config.ProxyAuthConfig
}

type IssueTokenInput struct {
	AssetID        int64  `json:"asset_id"`
	AccountID      int64  `json:"account_id"`
	Protocol       string `json:"protocol"`
	ConnectMethod  string `json:"connect_method"`
	IsReusable     bool   `json:"is_reusable"`
	ConnectOptions string `json:"connect_options"`
}

type VerifyTokenResult struct {
	Token   domain.ConnectionToken `json:"token"`
	User    domain.User            `json:"user"`
	Asset   domain.Asset           `json:"asset"`
	Account map[string]any         `json:"account"`
	// Target 连接目标信息，包含资产地址、协议端口和协议类型，供代理组件建立连接使用
	Target  VerifyTokenTarget      `json:"target"`
}

// VerifyTokenTarget 连接目标信息，描述验证通过后代理应该连接到哪里
type VerifyTokenTarget struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func NewTokenService(store *repository.Store, box *crypto.SecretBox, cfg config.ProxyAuthConfig) *TokenService {
	return &TokenService{store: store, box: box, cfg: cfg}
}

func (s *TokenService) Issue(userID int64, input IssueTokenInput) (domain.ConnectionToken, error) {
	if input.ConnectMethod == "" {
		input.ConnectMethod = "web_cli"
	}
	if input.Protocol == "" {
		input.Protocol = "ssh"
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

func (s *TokenService) Verify(value, proxySecret, remoteIP string) (VerifyTokenResult, error) {
	if !s.AuthorizeProxy(proxySecret, remoteIP) {
		return VerifyTokenResult{}, domain.ErrUnauthorized
	}
	token, err := s.store.GetConnectionToken(value)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	if time.Now().UTC().After(token.ExpiresAt) || (!token.IsReusable && token.UsedAt != nil) {
		return VerifyTokenResult{}, domain.ErrUnauthorized
	}
	user, err := s.store.GetUser(token.UserID)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	asset, err := s.store.GetAsset(token.AssetID)
	if err != nil {
		return VerifyTokenResult{}, err
	}
	account, err := s.store.GetAccount(token.AccountID)
	if err != nil {
		return VerifyTokenResult{}, err
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
	if !token.IsReusable {
		_ = s.store.MarkConnectionTokenUsed(token.Value)
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

// AuthorizeProxy 验证代理请求的合法性
// 同时校验代理密钥（X-Proxy-Auth）是否匹配配置的共享密钥，以及客户端 IP 是否在白名单内
// 返回 true 表示请求来自受信任的代理组件
func (s *TokenService) AuthorizeProxy(proxySecret, remoteIP string) bool {
	return proxySecret != "" && proxySecret == s.cfg.Secret && s.allowedIP(remoteIP)
}

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
