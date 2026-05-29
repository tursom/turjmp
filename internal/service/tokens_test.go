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

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
