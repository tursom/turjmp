package service

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// RDPProxyCredentialService 管理原生 RDP MITM 前端认证使用的用户级独立密码。
type RDPProxyCredentialService struct {
	store             *repository.Store
	passwordMinLength int
}

// RDPProxyCredentialStatus 是对外返回的凭据状态，不包含密码哈希。
type RDPProxyCredentialStatus struct {
	UserID     int64      `json:"user_id"`
	Configured bool       `json:"configured"`
	Enabled    bool       `json:"enabled"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
}

// RDPRouteUsername 是 mstsc 用户名路由格式的解析结果。
type RDPRouteUsername struct {
	Username  string `json:"username"`
	AssetID   int64  `json:"asset_id"`
	AccountID int64  `json:"account_id"`
}

// NewRDPProxyCredentialService 创建 RDPProxyCredentialService。
func NewRDPProxyCredentialService(store *repository.Store, passwordMinLength int) *RDPProxyCredentialService {
	return &RDPProxyCredentialService{store: store, passwordMinLength: passwordMinLength}
}

// Status 返回指定用户的 RDP 代理凭据状态。未配置不是错误。
func (s *RDPProxyCredentialService) Status(userID int64) (RDPProxyCredentialStatus, error) {
	if userID <= 0 {
		return RDPProxyCredentialStatus{}, domain.ErrInvalidArgument
	}
	if _, err := s.store.GetUser(userID); err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	credential, err := s.store.GetRDPProxyCredential(userID)
	if errors.Is(err, domain.ErrNotFound) {
		return RDPProxyCredentialStatus{UserID: userID}, nil
	}
	if err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	return credentialStatus(credential), nil
}

// Set 创建或覆盖指定用户的 RDP 代理密码，并重新启用凭据。
func (s *RDPProxyCredentialService) Set(userID int64, password string) (RDPProxyCredentialStatus, error) {
	if userID <= 0 || len(password) < s.effectivePasswordMinLength() {
		return RDPProxyCredentialStatus{}, domain.ErrInvalidArgument
	}
	if _, err := s.store.GetUser(userID); err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	credential, err := s.store.UpsertRDPProxyCredential(userID, hash)
	if err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	return credentialStatus(credential), nil
}

// Reset 覆盖为新密码并重新启用凭据。
func (s *RDPProxyCredentialService) Reset(userID int64, password string) (RDPProxyCredentialStatus, error) {
	return s.Set(userID, password)
}

// Disable 禁用指定用户的 RDP 代理凭据。
func (s *RDPProxyCredentialService) Disable(userID int64) (RDPProxyCredentialStatus, error) {
	if userID <= 0 {
		return RDPProxyCredentialStatus{}, domain.ErrInvalidArgument
	}
	credential, err := s.store.DisableRDPProxyCredential(userID)
	if err != nil {
		return RDPProxyCredentialStatus{}, err
	}
	return credentialStatus(credential), nil
}

// Verify 校验 RDP 代理前端用户名和独立密码，供后续 MITM 引擎认证回调使用。
func (s *RDPProxyCredentialService) Verify(username, password string) (domain.User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return domain.User{}, domain.ErrUnauthorized
	}
	user, err := s.store.GetUserByUsername(username)
	if err != nil || !user.IsActive {
		return domain.User{}, domain.ErrUnauthorized
	}
	credential, err := s.store.GetRDPProxyCredential(user.ID)
	if err != nil || !credential.IsEnabled {
		return domain.User{}, domain.ErrUnauthorized
	}
	ok, err := auth.VerifyPassword(password, credential.PasswordHash)
	if err != nil || !ok {
		return domain.User{}, domain.ErrUnauthorized
	}
	return user, nil
}

func (s *RDPProxyCredentialService) effectivePasswordMinLength() int {
	minLength := settingInt(s.store, "security.password_min_length", s.passwordMinLength)
	if minLength <= 0 {
		return s.passwordMinLength
	}
	return minLength
}

func credentialStatus(credential domain.RDPProxyCredential) RDPProxyCredentialStatus {
	updatedAt := credential.UpdatedAt
	return RDPProxyCredentialStatus{
		UserID:     credential.UserID,
		Configured: true,
		Enabled:    credential.IsEnabled,
		UpdatedAt:  &updatedAt,
		DisabledAt: credential.DisabledAt,
	}
}

// ParseRDPRouteUsername parses <turjmp_username>#<asset_id>#<account_id>.
func ParseRDPRouteUsername(raw string) (RDPRouteUsername, error) {
	parts := strings.Split(raw, "#")
	if len(parts) != 3 {
		return RDPRouteUsername{}, domain.ErrInvalidArgument
	}
	username := strings.TrimSpace(parts[0])
	assetID, err := parsePositiveRouteID(parts[1])
	if username == "" || err != nil {
		return RDPRouteUsername{}, domain.ErrInvalidArgument
	}
	accountID, err := parsePositiveRouteID(parts[2])
	if err != nil {
		return RDPRouteUsername{}, domain.ErrInvalidArgument
	}
	return RDPRouteUsername{Username: username, AssetID: assetID, AccountID: accountID}, nil
}

func parsePositiveRouteID(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, domain.ErrInvalidArgument
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, domain.ErrInvalidArgument
	}
	return id, nil
}
