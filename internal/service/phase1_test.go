package service

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

func TestPhase1BootstrapSeedsCoreData(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()

	roles, err := store.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(roles), 4; got != want {
		t.Fatalf("role count=%d want %d", got, want)
	}
	for _, roleName := range []string{"super_admin", "admin", "operator", "auditor"} {
		if _, err := store.GetRoleByName(roleName); err != nil {
			t.Fatalf("missing role %q: %v", roleName, err)
		}
	}

	admin, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	adminRoles, err := store.UserRoleNames(admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(adminRoles, "super_admin") {
		t.Fatalf("admin roles=%v, want super_admin", adminRoles)
	}

	platforms, err := store.ListPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(platforms), 4; got != want {
		t.Fatalf("platform count=%d want %d", got, want)
	}
	if linuxID := linuxPlatformID(t, store); linuxID == 0 {
		t.Fatal("missing Linux platform")
	}

	nodes, err := store.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "Default" || nodes[0].ParentID != nil {
		t.Fatalf("unexpected root nodes: %#v", nodes)
	}

	settings, err := store.ListSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(settings), len(repository.DefaultSettings()); got != want {
		t.Fatalf("setting count=%d want %d", got, want)
	}
	if setting, err := store.GetSetting("recording.storage"); err != nil || setting.Value != `"local"` {
		t.Fatalf("recording.storage=%#v err=%v", setting, err)
	}
}

func TestPhase1AuthLoginRefreshLogoutAndMFA(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	cfg := phase1ServiceConfig(t)
	jwtMgr, err := auth.NewJWTManager(cfg.JWT)
	if err != nil {
		t.Fatal(err)
	}
	authSvc := NewAuthService(store, jwtMgr, cfg)

	login, err := authSvc.Login("admin", "admin123", "")
	if err != nil {
		t.Fatal(err)
	}
	if login.AccessToken == "" || login.RefreshToken == "" {
		t.Fatalf("expected tokens in login result: %#v", login)
	}
	if login.User.Username != "admin" || !containsString(login.Roles, "super_admin") {
		t.Fatalf("unexpected login identity user=%#v roles=%v", login.User, login.Roles)
	}
	claims, err := authSvc.ParseAccessToken(login.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != login.User.ID || !containsString(claims.Roles, "super_admin") {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	refreshed, err := authSvc.Refresh(login.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("refresh token was not rotated: old=%q new=%q", login.RefreshToken, refreshed.RefreshToken)
	}
	if _, err := authSvc.Refresh(login.RefreshToken); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("old refresh token err=%v, want unauthorized", err)
	}
	if err := authSvc.Logout(login.User.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.Refresh(refreshed.RefreshToken); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("logout refresh err=%v, want unauthorized", err)
	}

	setup, err := authSvc.SetupMFA(login.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Secret == "" || !strings.HasPrefix(setup.URL, "otpauth://totp/") {
		t.Fatalf("unexpected mfa setup: %#v", setup)
	}
	code := totpCode(t, setup.Secret, time.Now().UTC())
	if err := authSvc.VerifyMFA(login.User.ID, code); err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.Login("admin", "admin123", ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("login without MFA err=%v, want unauthorized", err)
	}
	if mfaLogin, err := authSvc.Login("admin", "admin123", code); err != nil {
		t.Fatal(err)
	} else if !mfaLogin.User.MFAEnabled {
		t.Fatalf("expected MFA enabled user, got %#v", mfaLogin.User)
	}
}

func TestPhase1SettingsMaskAndEncryptSecretValues(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box := phase1SecretBox(t)
	settings := NewSettingService(store, box)
	if err := settings.Load(); err != nil {
		t.Fatal(err)
	}

	secret, err := settings.Get("recording.s3.access_key")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != `""` {
		t.Fatalf("empty default secret should not be masked, got %q", secret.Value)
	}

	updated, err := settings.Update("recording.s3.access_key", "minio-access-key")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Value != "******" {
		t.Fatalf("updated secret should be masked, got %q", updated.Value)
	}
	raw, err := store.GetSetting("recording.s3.access_key")
	if err != nil {
		t.Fatal(err)
	}
	if raw.Value == "minio-access-key" || !strings.HasPrefix(raw.Value, "enc:v1:") {
		t.Fatalf("secret was not encrypted at rest: %q", raw.Value)
	}
	decrypted, err := box.DecryptString(raw.Value)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "minio-access-key" {
		t.Fatalf("decrypted secret=%q", decrypted)
	}

	public, err := settings.Update("branding.site_name", `"Jumpbox"`)
	if err != nil {
		t.Fatal(err)
	}
	if public.Value != `"Jumpbox"` {
		t.Fatalf("public setting was unexpectedly masked: %#v", public)
	}
	grouped, err := settings.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped["recording"]) == 0 || len(grouped["branding"]) == 0 {
		t.Fatalf("settings not grouped by category: %#v", grouped)
	}
	for _, setting := range grouped["recording"] {
		if setting.Key == "recording.s3.access_key" && setting.Value != "******" {
			t.Fatalf("listed secret was not masked: %#v", setting)
		}
	}
}

func TestPhase1SessionDefaultsAndFinishUpdate(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	asset, account := createPhase1AssetAccount(t, store, phase1SecretBox(t))
	sessions := NewSessionService(store)

	created, err := sessions.Create(domain.Session{
		UserID:    1,
		AssetID:   asset.ID,
		AccountID: account.ID,
		Protocol:  "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Type != "normal" || created.LoginFrom != "WT" {
		t.Fatalf("unexpected session defaults: %#v", created)
	}

	updated, err := sessions.Update(created.ID, true, "recordings/session.cast")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.IsFinished || updated.DateEnd == nil || updated.RecordingPath != "recordings/session.cast" {
		t.Fatalf("session not finished correctly: %#v", updated)
	}
}

func TestPhase1TokenDefaultsPermissionsAndReusableVerify(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box := phase1SecretBox(t)
	asset, account := createPhase1AssetAccount(t, store, box)
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenService(store, box, phase1ServiceConfig(t).ProxyAuth)

	if _, err := tokens.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("issue without permission err=%v, want forbidden", err)
	}

	permission := domain.AssetPermission{Name: "connect test", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}

	token, err := tokens.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}
	if token.Protocol != "ssh" || token.ConnectMethod != "web_cli" || token.ConnectOptions != "{}" {
		t.Fatalf("unexpected token defaults: %#v", token)
	}
	if ttl := time.Until(token.ExpiresAt); ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Fatalf("unexpected token ttl %s", ttl)
	}
	result, err := tokens.Verify(token.Value, "proxy-secret", "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	if result.Target.Address != asset.Address || result.Target.Port != 22 || result.Target.Protocol != "ssh" {
		t.Fatalf("unexpected target: %#v", result.Target)
	}
	if result.Account["secret"] != "target-password" || result.Account["passphrase"] != "target-passphrase" {
		t.Fatalf("credentials were not decrypted: %#v", result.Account)
	}
	if _, err := tokens.Verify(token.Value, "proxy-secret", "127.0.0.1:2222"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("one-time token reuse err=%v, want unauthorized", err)
	}

	reusable, err := tokens.Issue(user.ID, IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, IsReusable: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Verify(reusable.Value, "proxy-secret", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Verify(reusable.Value, "proxy-secret", "127.0.0.1"); err != nil {
		t.Fatalf("reusable token second verify failed: %v", err)
	}
}

// TestSDKURLBuildsNativeConnectionFiles 验证原生客户端连接文件生成：
//  1. 准备：创建资产/账户，设置 db_name='appdb'
//  2. 测试无 connect 权限时被拒绝
//  3. 授予 connect 权限后测试 mysql/postgres/rdp 的 SDK URL 生成
//  4. 验证 mysql 命令行包含 username#token 格式（无密钥泄露）
//  5. 验证 postgres 命令行包含 -d appdb 参数
//  6. 验证 RDP 回退到 Web 客户端（非 .rdp 文件）
func TestSDKURLBuildsNativeConnectionFiles(t *testing.T) {
	store, closeFn := newMigratedTestStore(t)
	defer closeFn()
	box := phase1SecretBox(t)
	asset, account := createPhase1AssetAccount(t, store, box)
	if _, err := store.DB().Exec(`UPDATE accounts SET db_name = 'appdb' WHERE id = ?`, account.ID); err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenService(store, box, phase1ServiceConfig(t).ProxyAuth)
	cfg := config.ProxyConfig{
		APIBaseURL: "http://api.example.test:8080",
		SSH:        config.SSHProxyConfig{Addr: ":2222"},
		DB:         config.DBProxyConfig{MySQLAddr: ":3307", PostgresAddr: ":5437"},
		RDP:        config.RDPProxyConfig{Addr: ":33891"},
	}
	if _, err := tokens.BuildSDKURL(user.ID, SDKURLInput{
		IssueTokenInput: IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "mysql"},
	}, cfg); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("sdk without permission err=%v, want forbidden", err)
	}
	permission := domain.AssetPermission{Name: "connect sdk", Actions: "connect", IsActive: true}
	if err := store.CreatePermission(&permission, repository.PermissionLinks{
		UserIDs:    []int64{user.ID},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}); err != nil {
		t.Fatal(err)
	}

	mysql, err := tokens.BuildSDKURL(user.ID, SDKURLInput{
		IssueTokenInput: IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "mysql"},
		ProxyHost:       "bastion.example.test",
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if mysql.Protocol != "mysql" || mysql.Port != 3307 || mysql.ConnectMethod != "mysql_client" {
		t.Fatalf("unexpected mysql sdk: %#v", mysql)
	}
	if !strings.Contains(mysql.Command, "root#"+mysql.Token) || strings.Contains(mysql.Command, "target-password") {
		t.Fatalf("mysql command should contain username#token and no secret: %q", mysql.Command)
	}

	postgres, err := tokens.BuildSDKURL(user.ID, SDKURLInput{
		IssueTokenInput: IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "postgresql"},
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if postgres.Protocol != "postgres" || postgres.Host != "api.example.test" || !strings.Contains(postgres.Command, "-d appdb") {
		t.Fatalf("unexpected postgres sdk: %#v", postgres)
	}

	rdp, err := tokens.BuildSDKURL(user.ID, SDKURLInput{
		IssueTokenInput: IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "rdp"},
		ProxyHost:       "jump.example.test",
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rdp.ConnectMethod != "web_rdp" || rdp.WebURL == "" || strings.Contains(rdp.Content, ".rdp") {
		t.Fatalf("rdp should use web fallback sdk: %#v", rdp)
	}
}

func phase1ServiceConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	return config.Config{
		Security: config.SecurityConfig{
			EncryptionKey:     "phase-one-test-secret",
			PasswordMinLength: 8,
		},
		JWT: config.JWTConfig{
			PrivateKeyPath: filepath.Join(dir, "jwt_private.pem"),
			PublicKeyPath:  filepath.Join(dir, "jwt_public.pem"),
		},
		ProxyAuth: config.ProxyAuthConfig{
			Secret:     "proxy-secret",
			AllowedIPs: []string{"127.0.0.1", "::1"},
		},
		TOTP: config.TOTPConfig{Issuer: "Turjmp"},
	}
}

func phase1SecretBox(t *testing.T) *crypto.SecretBox {
	t.Helper()
	box, err := crypto.NewSecretBox(phase1ServiceConfig(t).Security.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func createPhase1AssetAccount(t *testing.T, store *repository.Store, box *crypto.SecretBox) (domain.Asset, domain.Account) {
	t.Helper()
	secret, err := box.EncryptString("target-password")
	if err != nil {
		t.Fatal(err)
	}
	passphrase, err := box.EncryptString("target-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	asset := domain.Asset{
		Name:       "phase1-linux",
		Address:    "10.0.0.10",
		PlatformID: linuxPlatformID(t, store),
		IsActive:   true,
	}
	if err := store.CreateAsset(&asset); err != nil {
		t.Fatal(err)
	}
	account := domain.Account{
		AssetID:    asset.ID,
		Name:       "root",
		Username:   "root",
		Secret:     secret,
		SecretType: "password",
		Passphrase: passphrase,
		IsActive:   true,
	}
	if err := store.CreateAccount(&account); err != nil {
		t.Fatal(err)
	}
	return asset, account
}

func linuxPlatformID(t *testing.T, store *repository.Store) int64 {
	t.Helper()
	platforms, err := store.ListPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range platforms {
		if platform.Name == "Linux" {
			return platform.ID
		}
	}
	t.Fatal("missing Linux platform")
	return 0
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(msg[:]); err != nil {
		t.Fatal(err)
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06s", strconv.FormatUint(uint64(binCode%1_000_000), 10))
}
