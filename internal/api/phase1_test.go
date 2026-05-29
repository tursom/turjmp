package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/rbac"
	"github.com/tursom/turjmp/internal/repository"
	"github.com/tursom/turjmp/internal/service"
)

func TestPhase1RouterHealthAuthAndRBAC(t *testing.T) {
	env := newPhase1APITestEnv(t)

	health := phase1Request(t, env.router, http.MethodGet, "/health", nil, nil)
	if health.Code != http.StatusOK {
		t.Fatalf("/health status=%d body=%s", health.Code, health.Body.String())
	}
	ready := phase1Request(t, env.router, http.MethodGet, "/health/ready", nil, nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("/health/ready status=%d body=%s", ready.Code, ready.Body.String())
	}

	unauthorized := phase1Request(t, env.router, http.MethodGet, "/api/v1/users", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("users without token status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	adminToken := phase1Login(t, env.router, "admin", "admin123")
	users := phase1Request(t, env.router, http.MethodGet, "/api/v1/users", nil, phase1AuthHeader(adminToken))
	if users.Code != http.StatusOK {
		t.Fatalf("users status=%d body=%s", users.Code, users.Body.String())
	}
	userList := phase1DecodeData[[]domain.User](t, users)
	if len(userList) == 0 || userList[0].Username != "admin" {
		t.Fatalf("unexpected user list: %#v", userList)
	}

	auditorRole, err := env.store.GetRoleByName("auditor")
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := service.NewUserService(env.store, 8).Create(service.CreateUserInput{
		Username: "auditor",
		Name:     "Auditor",
		Password: "auditor123",
		RoleIDs:  []int64{auditorRole.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if auditor.ID == 0 {
		t.Fatal("expected auditor user id")
	}
	auditorToken := phase1Login(t, env.router, "auditor", "auditor123")
	allowed := phase1Request(t, env.router, http.MethodGet, "/api/v1/sessions", nil, phase1AuthHeader(auditorToken))
	if allowed.Code != http.StatusOK {
		t.Fatalf("auditor sessions status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	forbidden := phase1Request(t, env.router, http.MethodGet, "/api/v1/assets", nil, phase1AuthHeader(auditorToken))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("auditor assets status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}
}

func TestPhase1RouterAssetsPermissionsTokensSettingsAndSessions(t *testing.T) {
	env := newPhase1APITestEnv(t)
	adminToken := phase1Login(t, env.router, "admin", "admin123")
	adminHeader := phase1AuthHeader(adminToken)

	updateSecret := phase1Request(t, env.router, http.MethodPut, "/api/v1/settings/recording.s3.access_key", gin.H{
		"value": "minio-access",
	}, adminHeader)
	if updateSecret.Code != http.StatusOK {
		t.Fatalf("update secret status=%d body=%s", updateSecret.Code, updateSecret.Body.String())
	}
	secretSetting := phase1DecodeData[domain.Setting](t, updateSecret)
	if secretSetting.Value != "******" {
		t.Fatalf("secret setting should be masked, got %#v", secretSetting)
	}
	rawSecret, err := env.store.GetSetting("recording.s3.access_key")
	if err != nil {
		t.Fatal(err)
	}
	if rawSecret.Value == "minio-access" {
		t.Fatal("secret setting was stored in plaintext")
	}

	fingerprints := phase1Request(t, env.router, http.MethodGet, "/api/v1/settings/ssh-fingerprint", nil, adminHeader)
	if fingerprints.Code != http.StatusOK {
		t.Fatalf("fingerprints status=%d body=%s", fingerprints.Code, fingerprints.Body.String())
	}
	type fingerprint struct {
		Algorithm   string `json:"algorithm"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"public_key"`
	}
	fpList := phase1DecodeData[[]fingerprint](t, fingerprints)
	if len(fpList) != 2 || fpList[0].Fingerprint == "" || fpList[0].PublicKey == "" {
		t.Fatalf("unexpected fingerprints: %#v", fpList)
	}

	assetResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/assets", domain.Asset{
		Name:       "phase1-linux",
		Address:    "10.0.0.10",
		PlatformID: phase1LinuxPlatformID(t, env.store),
		IsActive:   true,
	}, adminHeader)
	if assetResp.Code != http.StatusCreated {
		t.Fatalf("create asset status=%d body=%s", assetResp.Code, assetResp.Body.String())
	}
	asset := phase1DecodeData[domain.Asset](t, assetResp)
	if asset.ID == 0 || asset.Address != "10.0.0.10" {
		t.Fatalf("unexpected asset: %#v", asset)
	}

	accountResp := phase1Request(t, env.router, http.MethodPost, fmt.Sprintf("/api/v1/assets/%d/accounts", asset.ID), service.AccountInput{
		Name:       "root",
		Username:   "root",
		Secret:     "target-password",
		SecretType: "password",
		Passphrase: "target-passphrase",
	}, adminHeader)
	if accountResp.Code != http.StatusCreated {
		t.Fatalf("create account status=%d body=%s", accountResp.Code, accountResp.Body.String())
	}
	account := phase1DecodeData[domain.Account](t, accountResp)
	if account.ID == 0 || account.Secret != "" || account.Passphrase != "" {
		t.Fatalf("account response leaked secret fields: %#v", account)
	}
	getAccount := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/assets/%d/accounts/%d", asset.ID, account.ID), nil, adminHeader)
	if getAccount.Code != http.StatusOK {
		t.Fatalf("get account status=%d body=%s", getAccount.Code, getAccount.Body.String())
	}
	gotAccount := phase1DecodeData[domain.Account](t, getAccount)
	if gotAccount.Secret != "" || gotAccount.Passphrase != "" {
		t.Fatalf("get account leaked secret fields: %#v", gotAccount)
	}

	treeResp := phase1Request(t, env.router, http.MethodGet, "/api/v1/assets/tree", nil, adminHeader)
	if treeResp.Code != http.StatusOK {
		t.Fatalf("asset tree status=%d body=%s", treeResp.Code, treeResp.Body.String())
	}
	tree := phase1DecodeData[map[string]any](t, treeResp)
	if _, ok := tree["nodes"]; !ok {
		t.Fatalf("asset tree missing nodes: %#v", tree)
	}
	if _, ok := tree["assets"]; !ok {
		t.Fatalf("asset tree missing assets: %#v", tree)
	}

	permResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/permissions", service.PermissionInput{
		Name:       "allow admin connect",
		Actions:    []string{"connect"},
		UserIDs:    []int64{1},
		AssetIDs:   []int64{asset.ID},
		AccountIDs: []int64{account.ID},
	}, adminHeader)
	if permResp.Code != http.StatusCreated {
		t.Fatalf("create permission status=%d body=%s", permResp.Code, permResp.Body.String())
	}
	permission := phase1DecodeData[domain.AssetPermission](t, permResp)
	if permission.ID == 0 || permission.Actions != "connect" {
		t.Fatalf("unexpected permission: %#v", permission)
	}

	tokenResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/authentication/connection-tokens/", service.IssueTokenInput{
		AssetID:   asset.ID,
		AccountID: account.ID,
		Protocol:  "ssh",
	}, adminHeader)
	if tokenResp.Code != http.StatusCreated {
		t.Fatalf("issue token status=%d body=%s", tokenResp.Code, tokenResp.Body.String())
	}
	var issued struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	issued = phase1DecodeData[struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}](t, tokenResp)
	if issued.Token == "" || issued.ExpiresIn != 300 {
		t.Fatalf("unexpected token response: %#v", issued)
	}

	unauthorizedVerify := phase1Request(t, env.router, http.MethodPost, "/api/v1/authentication/super-connection-tokens/verify/", gin.H{
		"token": issued.Token,
	}, nil)
	if unauthorizedVerify.Code != http.StatusUnauthorized {
		t.Fatalf("verify without proxy auth status=%d body=%s", unauthorizedVerify.Code, unauthorizedVerify.Body.String())
	}
	verifyResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/authentication/super-connection-tokens/verify/", gin.H{
		"token": issued.Token,
	}, phase1ProxyHeader(env.cfg.ProxyAuth.Secret))
	if verifyResp.Code != http.StatusOK {
		t.Fatalf("verify token status=%d body=%s", verifyResp.Code, verifyResp.Body.String())
	}
	verify := phase1DecodeData[service.VerifyTokenResult](t, verifyResp)
	if verify.Target.Address != asset.Address || verify.Target.Port != 22 || verify.Account["secret"] != "target-password" {
		t.Fatalf("unexpected verify result: %#v", verify)
	}

	// 测试 SDK URL 端点拒绝未认证请求
	sdkUnauthorized := phase1Request(t, env.router, http.MethodPost, "/api/v1/authentication/connection-tokens/sdk-url", service.SDKURLInput{
		IssueTokenInput: service.IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "mysql"},
	}, nil)
	if sdkUnauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("sdk without auth status=%d body=%s", sdkUnauthorized.Code, sdkUnauthorized.Body.String())
	}
	// 测试 SDK URL POST 端点返回 mysql 协议的连接信息
	sdkResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/authentication/connection-tokens/sdk-url", service.SDKURLInput{
		IssueTokenInput: service.IssueTokenInput{AssetID: asset.ID, AccountID: account.ID, Protocol: "mysql"},
		ProxyHost:       "bastion.test",
	}, adminHeader)
	if sdkResp.Code != http.StatusCreated {
		t.Fatalf("sdk url status=%d body=%s", sdkResp.Code, sdkResp.Body.String())
	}
	sdk := phase1DecodeData[service.SDKURLResult](t, sdkResp)
	if sdk.Protocol != "mysql" || sdk.Port != 3307 || sdk.Token == "" || !strings.Contains(sdk.Command, "root#"+sdk.Token) {
		t.Fatalf("unexpected sdk result: %#v", sdk)
	}
	// 测试 SDK URL GET 端点通过查询参数请求 rdp 协议，返回 Web URL 回退
	rdpSDKResp := phase1Request(t, env.router, http.MethodGet,
		fmt.Sprintf("/api/v1/authentication/connection-tokens/sdk-url?asset_id=%d&account_id=%d&protocol=rdp&proxy_host=jump.test", asset.ID, account.ID),
		nil, adminHeader)
	if rdpSDKResp.Code != http.StatusCreated {
		t.Fatalf("rdp sdk url status=%d body=%s", rdpSDKResp.Code, rdpSDKResp.Body.String())
	}
	rdpSDK := phase1DecodeData[service.SDKURLResult](t, rdpSDKResp)
	if rdpSDK.WebURL == "" || rdpSDK.Filename != "turjmp-rdp.url" {
		t.Fatalf("unexpected rdp sdk result: %#v", rdpSDK)
	}

	sessionResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/sessions", domain.Session{
		UserID:     1,
		AssetID:    asset.ID,
		AccountID:  account.ID,
		Protocol:   "ssh",
		RemoteAddr: "127.0.0.1",
	}, adminHeader)
	if sessionResp.Code != http.StatusCreated {
		t.Fatalf("create session status=%d body=%s", sessionResp.Code, sessionResp.Body.String())
	}
	session := phase1DecodeData[domain.Session](t, sessionResp)
	if session.Type != "normal" || session.LoginFrom != "WT" {
		t.Fatalf("unexpected session defaults: %#v", session)
	}
	finishResp := phase1Request(t, env.router, http.MethodPatch, fmt.Sprintf("/api/v1/sessions/%d", session.ID), gin.H{
		"is_finished":    true,
		"recording_path": "recordings/phase1.cast",
	}, adminHeader)
	if finishResp.Code != http.StatusOK {
		t.Fatalf("finish session status=%d body=%s", finishResp.Code, finishResp.Body.String())
	}
	finished := phase1DecodeData[domain.Session](t, finishResp)
	if !finished.IsFinished || finished.DateEnd == nil || finished.RecordingPath != "recordings/phase1.cast" {
		t.Fatalf("session not finished: %#v", finished)
	}
}

func TestPhase1ProxyEndpointsRequireProxyAuth(t *testing.T) {
	env := newPhase1APITestEnv(t)

	noAuth := phase1Request(t, env.router, http.MethodGet, "/api/v1/proxy/settings/recording.storage", nil, nil)
	if noAuth.Code != http.StatusUnauthorized {
		t.Fatalf("proxy settings without auth status=%d body=%s", noAuth.Code, noAuth.Body.String())
	}
	withAuth := phase1Request(t, env.router, http.MethodGet, "/api/v1/proxy/settings/recording.storage", nil, phase1ProxyHeader(env.cfg.ProxyAuth.Secret))
	if withAuth.Code != http.StatusOK {
		t.Fatalf("proxy settings status=%d body=%s", withAuth.Code, withAuth.Body.String())
	}
	setting := phase1DecodeData[domain.Setting](t, withAuth)
	if setting.Key != "recording.storage" {
		t.Fatalf("unexpected proxy setting: %#v", setting)
	}

	hostKeys := phase1Request(t, env.router, http.MethodGet, "/api/v1/proxy/ssh/host-keys", nil, phase1ProxyHeader(env.cfg.ProxyAuth.Secret))
	if hostKeys.Code != http.StatusOK {
		t.Fatalf("proxy host keys status=%d body=%s", hostKeys.Code, hostKeys.Body.String())
	}
	var keys []struct {
		Algorithm  string `json:"algorithm"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	keys = phase1DecodeData[[]struct {
		Algorithm  string `json:"algorithm"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}](t, hostKeys)
	if len(keys) != 2 || keys[0].PrivateKey == "" || keys[0].PublicKey == "" {
		t.Fatalf("unexpected proxy host keys: %#v", keys)
	}
}

type phase1APITestEnv struct {
	router http.Handler
	store  *repository.Store
	cfg    config.Config
}

func newPhase1APITestEnv(t *testing.T) phase1APITestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "turjmp.db") + "?_pragma=foreign_keys(ON)"
	db, err := repository.NewDB(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := goose.Up(db.DB.DB, filepath.Join(phase1RepoRoot(t), "migrations", "sqlite")); err != nil {
		t.Fatal(err)
	}

	store := repository.NewStore(db)
	if err := store.BootstrapDefaults(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		App:      config.AppConfig{Name: "Turjmp", Environment: "test"},
		HTTP:     config.HTTPConfig{Addr: ":0", ShutdownTimeoutSeconds: 1},
		Database: config.DatabaseConfig{Driver: "sqlite", DSN: dsn, MigrationsDir: filepath.Join(phase1RepoRoot(t), "migrations", "sqlite")},
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
		TOTP:      config.TOTPConfig{Issuer: "Turjmp"},
		RateLimit: config.RateLimitConfig{Enabled: false},
	}
	box, err := crypto.NewSecretBox(cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	jwtMgr, err := auth.NewJWTManager(cfg.JWT)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := rbac.NewEnforcer(store)
	if err != nil {
		t.Fatal(err)
	}
	settings := service.NewSettingService(store, box)
	if err := settings.Load(); err != nil {
		t.Fatal(err)
	}
	h := &handler.Handler{
		Config:      cfg,
		Auth:        service.NewAuthService(store, jwtMgr, cfg),
		Users:       service.NewUserService(store, cfg.Security.PasswordMinLength),
		Assets:      service.NewAssetService(store, box),
		Permissions: service.NewPermissionService(store),
		Tokens:      service.NewTokenService(store, box, cfg.ProxyAuth),
		Settings:    settings,
		Sessions:    service.NewSessionService(store),
		HostKeys:    service.NewHostKeyService(store),
		Store:       store,
		Enforcer:    enforcer,
	}
	return phase1APITestEnv{router: NewRouter(cfg, zap.NewNop(), db, h), store: store, cfg: cfg}
}

func phase1Login(t *testing.T, router http.Handler, username, password string) string {
	t.Helper()
	resp := phase1Request(t, router, http.MethodPost, "/api/v1/auth/login", gin.H{
		"username": username,
		"password": password,
	}, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("login %s status=%d body=%s", username, resp.Code, resp.Body.String())
	}
	data := phase1DecodeData[struct {
		AccessToken string `json:"access_token"`
	}](t, resp)
	if data.AccessToken == "" {
		t.Fatalf("empty access token response: %s", resp.Body.String())
	}
	return data.AccessToken
}

func phase1Request(t *testing.T, router http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	req.RemoteAddr = "127.0.0.1:12345"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func phase1DecodeData[T any](t *testing.T, resp *httptest.ResponseRecorder) T {
	t.Helper()
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode body %s: %v", resp.Body.String(), err)
	}
	return envelope.Data
}

func phase1AuthHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func phase1ProxyHeader(secret string) map[string]string {
	return map[string]string{"X-Proxy-Auth": secret}
}

func phase1LinuxPlatformID(t *testing.T, store *repository.Store) int64 {
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

func phase1RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
