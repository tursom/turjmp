package service

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

func TestTokenServiceIssueAndVerifyReturnsTargetAndDecryptedAccount(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	platforms, err := store.ListPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	var linuxID int64
	for _, platform := range platforms {
		if platform.Name == "Linux" {
			linuxID = platform.ID
		}
	}
	if linuxID == 0 {
		t.Fatal("missing Linux platform")
	}
	if _, err := store.DB().Exec(`UPDATE platform_protocols SET port = 22222 WHERE name = 'ssh'`); err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{Name: "srv", Address: "10.0.0.10", PlatformID: linuxID, IsActive: true}
	if err := store.CreateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	secret, err := box.EncryptString("target-password")
	if err != nil {
		t.Fatal(err)
	}
	account := domain.Account{
		AssetID:    asset.ID,
		Name:       "root",
		Username:   "root",
		Secret:     secret,
		SecretType: "password",
		IsActive:   true,
	}
	if err := store.CreateAccount(&account); err != nil {
		t.Fatal(err)
	}
	permission := domain.AssetPermission{Name: "connect", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{
		Secret:     "proxy-secret",
		AllowedIPs: []string{"127.0.0.1"},
	})
	token, err := svc.Issue(user.ID, IssueTokenInput{
		AssetID:       asset.ID,
		AccountID:     account.ID,
		Protocol:      "ssh",
		ConnectMethod: "ssh_client",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1:5555")
	if err != nil {
		t.Fatal(err)
	}
	if result.Target.Address != "10.0.0.10" || result.Target.Port != 22222 || result.Target.Protocol != "ssh" {
		t.Fatalf("unexpected target: %#v", result.Target)
	}
	if got := result.Account["secret"]; got != "target-password" {
		t.Fatalf("decrypted secret=%#v", got)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1:5555"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected one-time token to be used, got %v", err)
	}
}

func TestTokenServiceIssueCanonicalizesPostgresProtocol(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	platforms, err := store.ListPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	var postgresID int64
	for _, platform := range platforms {
		if platform.Name == "PostgreSQL" {
			postgresID = platform.ID
		}
	}
	if postgresID == 0 {
		t.Fatal("missing PostgreSQL platform")
	}
	if _, err := store.DB().Exec(`UPDATE platform_protocols SET name = 'postgresql', port = 55432 WHERE platform_id = ? AND name = 'postgres'`, postgresID); err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{Name: "pg", Address: "10.0.0.20", PlatformID: postgresID, IsActive: true}
	if err := store.CreateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	secret, err := box.EncryptString("pg-password")
	if err != nil {
		t.Fatal(err)
	}
	account := domain.Account{
		AssetID:    asset.ID,
		Name:       "postgres",
		Username:   "postgres",
		Secret:     secret,
		SecretType: "password",
		DBName:     "app",
		IsActive:   true,
	}
	if err := store.CreateAccount(&account); err != nil {
		t.Fatal(err)
	}
	permission := domain.AssetPermission{Name: "connect pg", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{
		AssetID:   asset.ID,
		AccountID: account.ID,
		Protocol:  "postgresql",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.Protocol != "postgres" {
		t.Fatalf("token protocol=%q want postgres", token.Protocol)
	}
	result, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Target.Protocol != "postgres" || result.Target.Port != 55432 {
		t.Fatalf("unexpected target: %#v", result.Target)
	}
}

func TestTokenServiceRejectsInactiveAssetOrAccount(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	linuxID := linuxPlatformID(t, store)
	asset := domain.Asset{Name: "inactive-check", Address: "10.0.0.30", PlatformID: linuxID, IsActive: true}
	if err := store.CreateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	secret, err := box.EncryptString("target-password")
	if err != nil {
		t.Fatal(err)
	}
	account := domain.Account{
		AssetID:    asset.ID,
		Name:       "root",
		Username:   "root",
		Secret:     secret,
		SecretType: "password",
		IsActive:   true,
	}
	if err := store.CreateAccount(&account); err != nil {
		t.Fatal(err)
	}
	permission := domain.AssetPermission{Name: "connect inactive check", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}
	account.IsActive = false
	if err := store.UpdateAccount(&account); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("inactive account issue err=%v, want forbidden", err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("inactive account verify err=%v, want forbidden", err)
	}
	account.IsActive = true
	if err := store.UpdateAccount(&account); err != nil {
		t.Fatal(err)
	}
	asset.IsActive = false
	if err := store.UpdateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("inactive asset issue err=%v, want forbidden", err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("inactive asset verify err=%v, want forbidden", err)
	}
}

func TestTokenServiceVerifyRejectsDisabledUser(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	asset, account := createTokenTestAssetAccount(t, store, box, "disabled-user")
	permission := domain.AssetPermission{Name: "connect disabled user", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}

	user.IsActive = false
	if err := store.UpdateUser(&user); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("disabled user verify err=%v, want unauthorized", err)
	}
	stored, err := store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt != nil {
		t.Fatal("disabled user verification should not consume token")
	}
}

func TestTokenServiceVerifyRejectsRevokedPermission(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	asset, account := createTokenTestAssetAccount(t, store, box, "revoked-permission")
	permission := domain.AssetPermission{Name: "connect revoked permission", Actions: "connect", IsActive: true}
	links := repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}
	if err := store.CreatePermission(&permission, links); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}

	permission.IsActive = false
	if err := store.UpdatePermission(&permission, links); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("revoked permission verify err=%v, want forbidden", err)
	}
	stored, err := store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt != nil {
		t.Fatal("revoked permission verification should not consume token")
	}
}

func TestTokenServiceVerifyRequiresProxyAuthorization(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{
		Secret:     "proxy-secret",
		AllowedIPs: []string{"127.0.0.1"},
	})
	if _, err := svc.Verify("missing", "", "127.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("empty secret err=%v", err)
	}
	if _, err := svc.Verify("missing", "proxy-secret", "10.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("disallowed ip err=%v", err)
	}
	if !svc.AuthorizeProxy("proxy-secret", "127.0.0.1:1234") {
		t.Fatal("expected allowed proxy")
	}
}

func TestTokenServiceVerifyConsumesOneTimeTokenAtomically(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	asset, account := createTokenTestAssetAccount(t, store, box, "one-time")
	permission := domain.AssetPermission{Name: "connect one time", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{
		AssetID:   asset.ID,
		AccountID: account.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); err != nil {
		t.Fatalf("first verify err=%v", err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("second verify err=%v, want unauthorized", err)
	}
	consumed, err := store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.UsedAt == nil {
		t.Fatal("expected one-time token to be marked used")
	}
}

func TestTokenServiceExpectedProtocolMismatchDoesNotConsumeToken(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	asset, account := createTokenTestAssetAccount(t, store, box, "protocol-mismatch")
	permission := domain.AssetPermission{Name: "connect protocol mismatch", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{
		AssetID:   asset.ID,
		AccountID: account.ID,
		Protocol:  "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyWithOptions(token.Value, "proxy-secret", "127.0.0.1", VerifyTokenOptions{
		ExpectedProtocol: "mysql",
		Consume:          true,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("protocol mismatch err=%v, want forbidden", err)
	}
	stored, err := store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt != nil {
		t.Fatal("protocol mismatch should not consume token")
	}
	if _, err := svc.VerifyWithOptions(token.Value, "proxy-secret", "127.0.0.1", VerifyTokenOptions{
		ExpectedProtocol: "ssh",
		Consume:          false,
	}); err != nil {
		t.Fatalf("preflight verify err=%v", err)
	}
	stored, err = store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt != nil {
		t.Fatal("preflight should not consume token")
	}
	if _, err := svc.VerifyWithOptions(token.Value, "proxy-secret", "127.0.0.1", VerifyTokenOptions{
		ExpectedProtocol: "ssh",
		Consume:          true,
	}); err != nil {
		t.Fatalf("consume verify after preflight err=%v", err)
	}
}

func TestTokenServiceVerifyAllowsReusableTokenRepeatedly(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box, err := crypto.NewSecretBox("test-secret")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	asset, account := createTokenTestAssetAccount(t, store, box, "reusable")
	permission := domain.AssetPermission{Name: "connect reusable", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}
	svc := NewTokenService(store, box, config.ProxyAuthConfig{Secret: "proxy-secret"})
	token, err := svc.Issue(user.ID, IssueTokenInput{
		AssetID:    asset.ID,
		AccountID:  account.ID,
		IsReusable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); err != nil {
		t.Fatalf("first verify err=%v", err)
	}
	if _, err := svc.Verify(token.Value, "proxy-secret", "127.0.0.1"); err != nil {
		t.Fatalf("second verify err=%v", err)
	}
	reusable, err := store.GetConnectionToken(token.Value)
	if err != nil {
		t.Fatal(err)
	}
	if reusable.UsedAt != nil {
		t.Fatal("reusable token should not be marked used")
	}
}

func newMigratedTestStore(t *testing.T) (*repository.Store, func()) {
	t.Helper()
	db, err := repository.NewDB(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    "file:" + filepath.Join(t.TempDir(), "turjmp.db") + "?_pragma=foreign_keys(ON)",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := goose.Up(db.DB.DB, filepath.Join(repoRoot(t), "migrations", "sqlite")); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	store := repository.NewStore(db)
	if err := store.BootstrapDefaults(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return store, func() { _ = db.Close() }
}

func createTokenTestAssetAccount(t *testing.T, store *repository.Store, box *crypto.SecretBox, suffix string) (domain.Asset, domain.Account) {
	t.Helper()
	asset := domain.Asset{
		Name:       "srv-" + suffix,
		Address:    "10.0.1.10",
		PlatformID: linuxPlatformID(t, store),
		IsActive:   true,
	}
	if err := store.CreateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	secret, err := box.EncryptString("target-password")
	if err != nil {
		t.Fatal(err)
	}
	account := domain.Account{
		AssetID:    asset.ID,
		Name:       "root",
		Username:   "root",
		Secret:     secret,
		SecretType: "password",
		IsActive:   true,
	}
	if err := store.CreateAccount(&account); err != nil {
		t.Fatal(err)
	}
	return asset, account
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
