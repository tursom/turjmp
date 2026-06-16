package service

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/tursom/turjmp/internal/config"
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

// NativeRDPSessionStartInput starts a native RDP MITM session.
type NativeRDPSessionStartInput struct {
	RouteUsername string `json:"route_username"`
	Password      string `json:"password"`
	RemoteAddr    string `json:"remote_addr"`
}

// NativeRDPSessionStartResult contains target credentials plus the Turjmp session ID.
type NativeRDPSessionStartResult struct {
	SessionID int64                    `json:"session_id"`
	UserID    int64                    `json:"user_id"`
	AssetID   int64                    `json:"asset_id"`
	AccountID int64                    `json:"account_id"`
	Target    NativeRDPResolvedTarget  `json:"target"`
	Account   NativeRDPResolvedAccount `json:"account"`
}

// NativeRDPSessionFinishInput completes a native RDP MITM session.
type NativeRDPSessionFinishInput struct {
	Reason string `json:"reason"`
}

// NativeRDPSessionFinishResult reports whether this call changed session state.
type NativeRDPSessionFinishResult struct {
	SessionID int64  `json:"session_id"`
	Finished  bool   `json:"finished"`
	Reason    string `json:"reason"`
}

// NativeRDPSessionCleanupResult reports proxy-shutdown cleanup for active native RDP sessions.
type NativeRDPSessionCleanupResult struct {
	Reason   string  `json:"reason"`
	Finished []int64 `json:"finished"`
	Skipped  []int64 `json:"skipped,omitempty"`
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

// StartSession validates native RDP credentials, creates a session, and writes audit records.
func (s *NativeRDPResolverService) StartSession(input NativeRDPSessionStartInput, proxyCfg config.ProxyConfig) (NativeRDPSessionStartResult, error) {
	resolveInput := NativeRDPResolveInput{
		RouteUsername: input.RouteUsername,
		Password:      input.Password,
		RemoteAddr:    input.RemoteAddr,
	}
	resolved, err := s.Resolve(resolveInput)
	if err != nil {
		s.auditNativeRDPDenied(input, err)
		return NativeRDPSessionStartResult{}, err
	}
	session := domain.Session{
		UserID:     resolved.UserID,
		AssetID:    resolved.AssetID,
		AccountID:  resolved.AccountID,
		Protocol:   "rdp",
		Type:       "rdp",
		LoginFrom:  "rdp_client",
		RemoteAddr: input.RemoteAddr,
	}
	created, err := s.store.CreateSessionUnderActiveLimit(&session, proxyCfg.RDP.ConnectionLimit())
	if err != nil {
		return NativeRDPSessionStartResult{}, err
	}
	if !created {
		s.auditNativeRDP(&resolved.UserID, "rdp.native.denied", "rdp", input.RemoteAddr, nativeRDPAuditDetail(nativeRDPAuditPayload{
			AssetID:   resolved.AssetID,
			AccountID: resolved.AccountID,
			Reason:    "max_connections",
		}))
		return NativeRDPSessionStartResult{}, nativeRDPResolveDenied("max_connections", domain.ErrForbidden)
	}
	s.auditNativeRDP(&resolved.UserID, "rdp.native.start", "rdp", input.RemoteAddr, nativeRDPAuditDetail(nativeRDPAuditPayload{
		SessionID: session.ID,
		AssetID:   resolved.AssetID,
		AccountID: resolved.AccountID,
		Reason:    "started",
	}))
	return NativeRDPSessionStartResult{
		SessionID: session.ID,
		UserID:    resolved.UserID,
		AssetID:   resolved.AssetID,
		AccountID: resolved.AccountID,
		Target:    resolved.Target,
		Account:   resolved.Account,
	}, nil
}

// FinishSession marks a native RDP session finished once and writes a completion audit once.
func (s *NativeRDPResolverService) FinishSession(sessionID int64, input NativeRDPSessionFinishInput) (NativeRDPSessionFinishResult, error) {
	if sessionID <= 0 {
		return NativeRDPSessionFinishResult{}, domain.ErrInvalidArgument
	}
	reason := sanitizeNativeRDPReason(input.Reason)
	existing, err := s.store.GetSession(sessionID)
	if err != nil {
		return NativeRDPSessionFinishResult{}, err
	}
	if existing.Protocol != "rdp" || existing.Type != "rdp" || existing.LoginFrom != "rdp_client" {
		return NativeRDPSessionFinishResult{}, domain.ErrForbidden
	}
	session, changed, err := s.store.FinishSessionOnce(sessionID, "")
	if err != nil {
		return NativeRDPSessionFinishResult{}, err
	}
	if changed {
		s.auditNativeRDP(&session.UserID, nativeRDPFinishAction(reason), "rdp", session.RemoteAddr, nativeRDPAuditDetail(nativeRDPAuditPayload{
			SessionID: session.ID,
			AssetID:   session.AssetID,
			AccountID: session.AccountID,
			Reason:    reason,
		}))
	}
	return NativeRDPSessionFinishResult{SessionID: session.ID, Finished: changed, Reason: reason}, nil
}

// FinishActiveSessions marks all active native RDP client sessions complete for proxy shutdown cleanup.
func (s *NativeRDPResolverService) FinishActiveSessions(input NativeRDPSessionFinishInput) (NativeRDPSessionCleanupResult, error) {
	reason := sanitizeNativeRDPReason(input.Reason)
	ids, err := s.store.ListActiveNativeRDPSessionIDs()
	if err != nil {
		return NativeRDPSessionCleanupResult{}, err
	}
	result := NativeRDPSessionCleanupResult{Reason: reason, Finished: []int64{}, Skipped: []int64{}}
	for _, id := range ids {
		finished, err := s.FinishSession(id, NativeRDPSessionFinishInput{Reason: reason})
		if err != nil {
			return NativeRDPSessionCleanupResult{}, err
		}
		if finished.Finished {
			result.Finished = append(result.Finished, id)
		} else {
			result.Skipped = append(result.Skipped, id)
		}
	}
	return result, nil
}

func nativeRDPResolveDenied(reason string, err error) error {
	return &NativeRDPResolveError{Reason: reason, Err: err}
}

type nativeRDPAuditPayload struct {
	SessionID int64  `json:"session_id,omitempty"`
	AssetID   int64  `json:"asset_id,omitempty"`
	AccountID int64  `json:"account_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
}

func nativeRDPAuditDetail(payload nativeRDPAuditPayload) string {
	payload.Protocol = "rdp"
	payload.Source = "rdp_client"
	raw, err := json.Marshal(payload)
	if err != nil {
		return `{"protocol":"rdp","source":"rdp_client","reason":"marshal_failed"}`
	}
	return string(raw)
}

func (s *NativeRDPResolverService) auditNativeRDP(userID *int64, action, resource, remoteAddr, detail string) {
	_ = s.store.Audit(userID, action, resource, remoteAddr, detail)
}

func (s *NativeRDPResolverService) auditNativeRDPDenied(input NativeRDPSessionStartInput, err error) {
	reason := "denied"
	var resolveErr *NativeRDPResolveError
	if errors.As(err, &resolveErr) && resolveErr.Reason != "" {
		reason = resolveErr.Reason
	}
	route, parseErr := ParseRDPRouteUsername(input.RouteUsername)
	var userID *int64
	if parseErr == nil {
		if user, getErr := s.store.GetUserByUsername(route.Username); getErr == nil {
			userID = &user.ID
		}
	}
	payload := nativeRDPAuditPayload{Reason: reason}
	if parseErr == nil {
		payload.AssetID = route.AssetID
		payload.AccountID = route.AccountID
	}
	s.auditNativeRDP(userID, "rdp.native.denied", "rdp", input.RemoteAddr, nativeRDPAuditDetail(payload))
}

func sanitizeNativeRDPReason(reason string) string {
	reason = strings.TrimSpace(strings.ToLower(reason))
	if reason == "" {
		return "disconnect"
	}
	var b strings.Builder
	for _, r := range reason {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "disconnect"
	}
	return b.String()
}

func nativeRDPFinishAction(reason string) string {
	switch reason {
	case "target_login_failed", "target_connect_failed", "target_dial_failed", "idle_timeout", "proxy_shutdown":
		return "rdp.native." + reason
	default:
		if strings.HasPrefix(reason, "target_") {
			return "rdp.native.target_failure"
		}
		if _, err := strconv.ParseInt(reason, 10, 64); err == nil {
			return "rdp.native.disconnect"
		}
		return "rdp.native.complete"
	}
}
