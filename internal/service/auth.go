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

type AuthService struct {
	store *repository.Store
	jwt   *auth.JWTManager
	cfg   config.Config
}

type LoginResult struct {
	AccessToken           string      `json:"access_token"`
	AccessTokenExpiresAt  time.Time   `json:"access_token_expires_at"`
	RefreshToken          string      `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time   `json:"refresh_token_expires_at"`
	User                  domain.User `json:"user"`
	Roles                 []string    `json:"roles"`
}

func NewAuthService(store *repository.Store, jwt *auth.JWTManager, cfg config.Config) *AuthService {
	return &AuthService{store: store, jwt: jwt, cfg: cfg}
}

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

func (s *AuthService) Logout(userID int64) error {
	return s.store.RevokeUserRefreshTokens(userID)
}

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

func (s *AuthService) ParseAccessToken(raw string) (*auth.Claims, error) {
	return s.jwt.ParseAccessToken(raw)
}

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

func IsAuthError(err error) bool {
	return errors.Is(err, domain.ErrUnauthorized)
}
