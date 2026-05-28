// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责认证、用户管理、资产管理等核心业务流程的编排与验证。
package service

import (
	"errors"
	"strings"
	"time"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// AuthService 认证服务，封装用户登录、令牌签发与刷新、MFA 多因素认证、登出等认证相关的全部业务逻辑。依赖 Store 进行持久化、JWTManager 管理 JWT 令牌、Config 提供 TOTP 签发者等配置。
type AuthService struct {
	store *repository.Store
	jwt   *auth.JWTManager
	cfg   config.Config
}

// LoginResult 登录成功后返回的完整结果，包含访问令牌和刷新令牌及其过期时间、用户信息与角色列表，供前端存储并后续请求使用。
type LoginResult struct {
	AccessToken           string      `json:"access_token"`
	AccessTokenExpiresAt  time.Time   `json:"access_token_expires_at"`
	RefreshToken          string      `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time   `json:"refresh_token_expires_at"`
	User                  domain.User `json:"user"`
	Roles                 []string    `json:"roles"`
}

// NewAuthService 创建 AuthService 实例，注入存储层、JWT 管理器和应用配置。
func NewAuthService(store *repository.Store, jwt *auth.JWTManager, cfg config.Config) *AuthService {
	return &AuthService{store: store, jwt: jwt, cfg: cfg}
}

// Login 处理用户登录请求。业务流程：根据用户名查找用户 → 检查用户是否激活 → 验证密码（argon2id）→ 若用户已启用 MFA 则校验 TOTP 一次性验证码 → 更新最后登录时间 → 调用 issueTokens 签发令牌对。
// 任意一步失败均返回 domain.ErrUnauthorized 以隐藏具体失败原因，防止用户枚举攻击。
func (s *AuthService) Login(username, password, mfaCode string) (LoginResult, error) {
	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		return LoginResult{}, domain.ErrUnauthorized
	}
	if !user.IsActive {
		return LoginResult{}, domain.ErrUnauthorized
	}
	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		return LoginResult{}, domain.ErrUnauthorized
	}
	if user.MFAEnabled && !auth.ValidateTOTP(mfaCode, user.MFASecret) {
		return LoginResult{}, domain.ErrUnauthorized
	}
	_ = s.store.TouchUserLogin(user.ID)
	return s.issueTokens(user)
}

// Refresh 使用刷新令牌轮换获取新的令牌对。流程：对传入的原始刷新令牌做哈希 → 在数据库中查找对应的存储记录 → 校验未被撤销且未过期 → 立即撤销旧的刷新令牌（防止重放）→ 查找用户 → 签发新的令牌对（refresh token rotation 模式）。
// 若刷新令牌无效、已撤销或已过期，返回 domain.ErrUnauthorized。
func (s *AuthService) Refresh(refreshToken string) (LoginResult, error) {
	hash := auth.HashRefreshToken(refreshToken)
	stored, err := s.store.GetRefreshTokenByHash(hash)
	if err != nil || stored.RevokedAt != nil || time.Now().UTC().After(stored.ExpiresAt) {
		return LoginResult{}, domain.ErrUnauthorized
	}
	if err := s.store.RevokeRefreshToken(stored.ID); err != nil {
		return LoginResult{}, err
	}
	user, err := s.store.GetUser(stored.UserID)
	if err != nil {
		return LoginResult{}, err
	}
	return s.issueTokens(user)
}

// Logout 登出指定用户，撤销其所有有效的刷新令牌，使其所有已签发的刷新令牌失效。
func (s *AuthService) Logout(userID int64) error {
	return s.store.RevokeUserRefreshTokens(userID)
}

// SetupMFA 为指定用户生成 TOTP 多因素认证设置。生成新的 TOTP 密钥和对应的 provisioning URI，将密钥存入用户记录后返回设置结果（含 QR 码链接供前端展示）。
func (s *AuthService) SetupMFA(userID int64) (auth.TOTPSetup, error) {
	user, err := s.store.GetUser(userID)
	if err != nil {
		return auth.TOTPSetup{}, err
	}
	setup, err := auth.GenerateTOTP(s.cfg.TOTP.Issuer, user.Username)
	if err != nil {
		return auth.TOTPSetup{}, err
	}
	user.MFASecret = setup.Secret
	if err := s.store.UpdateUser(&user); err != nil {
		return auth.TOTPSetup{}, err
	}
	return setup, nil
}

// VerifyMFA 验证 TOTP 验证码并将用户的 MFA 状态标记为已启用。仅在用户已持有 MFA 密钥（通过 SetupMFA 设置）后调用，验证通过后将 MFAEnabled 设为 true。
func (s *AuthService) VerifyMFA(userID int64, code string) error {
	user, err := s.store.GetUser(userID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(user.MFASecret) == "" || !auth.ValidateTOTP(code, user.MFASecret) {
		return domain.ErrUnauthorized
	}
	user.MFAEnabled = true
	return s.store.UpdateUser(&user)
}

// ParseAccessToken 解析原始 JWT 访问令牌字符串，返回包含用户 ID、用户名、角色等信息的 Claims 结构体。委托给底层 JWTManager 完成签名验证与解析。
func (s *AuthService) ParseAccessToken(raw string) (*auth.Claims, error) {
	return s.jwt.ParseAccessToken(raw)
}

// issueTokens 为指定用户签发一对令牌（访问令牌 + 刷新令牌），并返回 LoginResult。流程：获取用户角色名称列表 → 用 JWT RS256 签发访问令牌 → 生成刷新令牌（UUID，存储哈希后的值）→ 将刷新令牌哈希存入数据库 → 组装 LoginResult 返回。
// 该方法是内部方法，被 Login 和 Refresh 共同调用。
func (s *AuthService) issueTokens(user domain.User) (LoginResult, error) {
	roles, err := s.store.UserRoleNames(user.ID)
	if err != nil {
		return LoginResult{}, err
	}
	access, accessExpires, err := s.jwt.SignAccessToken(user.ID, user.Username, roles)
	if err != nil {
		return LoginResult{}, err
	}
	refreshID, refreshRaw, refreshHash, refreshExpires, err := s.jwt.NewRefreshToken()
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.store.CreateRefreshToken(domain.RefreshToken{
		ID:        refreshID,
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: refreshExpires,
	}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		AccessToken:           access,
		AccessTokenExpiresAt:  accessExpires,
		RefreshToken:          refreshRaw,
		RefreshTokenExpiresAt: refreshExpires,
		User:                  user,
		Roles:                 roles,
	}, nil
}

// IsAuthError 判断给定的 error 是否为认证错误（即 domain.ErrUnauthorized），供上层调用方快速判断是否需要跳转登录页或返回 401。
func IsAuthError(err error) bool {
	return errors.Is(err, domain.ErrUnauthorized)
}
