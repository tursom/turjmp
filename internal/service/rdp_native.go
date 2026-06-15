package service

import (
	"errors"
	"strings"

	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// NativeRDPResolverService resolves mstsc front-side credentials into a managed target RDP login.
type NativeRDPResolverService struct {
	store             *repository.Store
	box               *crypto.SecretBox
	passwordMinLength int
}

// NativeRDPResolveInput is the proxy-auth request payload used by the native RDP engine callback.
type NativeRDPResolveInput struct {
	RouteUsername string `json:"route_username"`
	Password      string `json:"password"`
	RemoteAddr    string `json:"remote_addr"`
}

// NativeRDPResolveResult contains only the identity and target credentials needed by the RDP MITM engine.
type NativeRDPResolveResult struct {
	UserID    int64                    `json:"user_id"`
	AssetID   int64                    `json:"asset_id"`
	AccountID int64                    `json:"account_id"`
	Target    NativeRDPResolvedTarget  `json:"target"`
	Account   NativeRDPResolvedAccount `json:"account"`
}

// NativeRDPResolvedTarget describes the RDP endpoint selected from the managed asset.
type NativeRDPResolvedTarget struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// NativeRDPResolvedAccount contains the target Windows account credentials.
type NativeRDPResolvedAccount struct {
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
}

// NativeRDPResolveError keeps a redacted denial reason for logs/tests while preserving public error classes.
type NativeRDPResolveError struct {
	Reason string
	Err    error
}

func (e *NativeRDPResolveError) Error() string {
	if e == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *NativeRDPResolveError) Unwrap() error {
	return e.Err
}

// NewNativeRDPResolverService creates the native RDP route/auth resolver.
func NewNativeRDPResolverService(store *repository.Store, box *crypto.SecretBox, passwordMinLength int) *NativeRDPResolverService {
	return &NativeRDPResolverService{store: store, box: box, passwordMinLength: passwordMinLength}
}

// Resolve validates the front-side RDP proxy credential and resolves the managed target password.
func (s *NativeRDPResolverService) Resolve(input NativeRDPResolveInput) (NativeRDPResolveResult, error) {
	route, err := ParseRDPRouteUsername(input.RouteUsername)
	if err != nil {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("malformed_route_username", domain.ErrUnauthorized)
	}
	credentialService := NewRDPProxyCredentialService(s.store, s.passwordMinLength)
	user, err := credentialService.Verify(route.Username, input.Password)
	if err != nil {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("front_auth_failed", domain.ErrUnauthorized)
	}
	asset, err := s.store.GetAsset(route.AssetID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return NativeRDPResolveResult{}, nativeRDPResolveDenied("asset_not_found", domain.ErrForbidden)
		}
		return NativeRDPResolveResult{}, err
	}
	account, err := s.store.GetAssetAccount(route.AssetID, route.AccountID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return NativeRDPResolveResult{}, nativeRDPResolveDenied("account_not_found", domain.ErrForbidden)
		}
		return NativeRDPResolveResult{}, err
	}
	if !asset.IsActive {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("asset_inactive", domain.ErrForbidden)
	}
	if !account.IsActive {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("account_inactive", domain.ErrForbidden)
	}
	ok, err := s.store.HasAssetPermission(user.ID, route.AssetID, route.AccountID, "connect")
	if err != nil {
		return NativeRDPResolveResult{}, err
	}
	if !ok {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("missing_connect_permission", domain.ErrForbidden)
	}
	port, err := s.store.GetAssetProtocolPort(route.AssetID, "rdp")
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return NativeRDPResolveResult{}, nativeRDPResolveDenied("rdp_protocol_not_available", domain.ErrForbidden)
		}
		return NativeRDPResolveResult{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(account.SecretType), "password") {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("target_secret_type_not_password", domain.ErrForbidden)
	}
	secret, err := s.box.DecryptString(account.Secret)
	if err != nil {
		return NativeRDPResolveResult{}, err
	}
	if secret == "" {
		return NativeRDPResolveResult{}, nativeRDPResolveDenied("target_password_empty", domain.ErrForbidden)
	}
	return NativeRDPResolveResult{
		UserID:    user.ID,
		AssetID:   asset.ID,
		AccountID: account.ID,
		Target: NativeRDPResolvedTarget{
			Address:  asset.Address,
			Port:     port,
			Protocol: "rdp",
		},
		Account: NativeRDPResolvedAccount{
			Username:   account.Username,
			Secret:     secret,
			SecretType: "password",
		},
	}, nil
}

func nativeRDPResolveDenied(reason string, err error) error {
	return &NativeRDPResolveError{Reason: reason, Err: err}
}
