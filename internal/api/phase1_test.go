package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
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

	operatorRole, err := env.store.GetRoleByName("operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.NewUserService(env.store, 8).Create(service.CreateUserInput{
		Username: "operator",
		Name:     "Operator",
		Password: "operator123",
		RoleIDs:  []int64{operatorRole.ID},
	}); err != nil {
		t.Fatal(err)
	}
	operatorToken := phase1Login(t, env.router, "operator", "operator123")
	accessResp := phase1Request(t, env.router, http.MethodGet, "/api/v1/auth/access", nil, phase1AuthHeader(operatorToken))
	if accessResp.Code != http.StatusOK {
		t.Fatalf("operator access status=%d body=%s", accessResp.Code, accessResp.Body.String())
	}
	access := phase1DecodeData[struct {
		Access map[string]bool `json:"access"`
	}](t, accessResp)
	for _, key := range []string{"connection_tokens", "assets", "accounts", "platforms", "platform_protocols"} {
		if !access.Access[key] {
			t.Fatalf("operator access[%s]=false, access=%#v", key, access.Access)
		}
	}
	if access.Access["user_rdp_proxy_credential"] {
		t.Fatalf("operator should not manage user rdp proxy credentials, access=%#v", access.Access)
	}
}

func TestPhase1RDPProxyCredentialAPIs(t *testing.T) {
	env := newPhase1APITestEnv(t)

	unauthorized := phase1Request(t, env.router, http.MethodGet, "/api/v1/auth/rdp-proxy-credential", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("self credential without token status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	adminToken := phase1Login(t, env.router, "admin", "admin123")
	adminHeader := phase1AuthHeader(adminToken)
	statusResp := phase1Request(t, env.router, http.MethodGet, "/api/v1/auth/rdp-proxy-credential", nil, adminHeader)
	if statusResp.Code != http.StatusOK {
		t.Fatalf("self credential status=%d body=%s", statusResp.Code, statusResp.Body.String())
	}
	status := phase1DecodeData[service.RDPProxyCredentialStatus](t, statusResp)
	if status.Configured || status.Enabled || status.UserID != 1 {
		t.Fatalf("unexpected empty self status: %#v", status)
	}

	setResp := phase1Request(t, env.router, http.MethodPut, "/api/v1/auth/rdp-proxy-credential", gin.H{
		"password": "rdp-admin-pass-1",
	}, adminHeader)
	if setResp.Code != http.StatusOK {
		t.Fatalf("self credential set status=%d body=%s", setResp.Code, setResp.Body.String())
	}
	phase1AssertNoCredentialSecretLeak(t, setResp.Body.String())
	setStatus := phase1DecodeData[service.RDPProxyCredentialStatus](t, setResp)
	if !setStatus.Configured || !setStatus.Enabled || setStatus.UpdatedAt == nil {
		t.Fatalf("unexpected set self status: %#v", setStatus)
	}

	resetResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/auth/rdp-proxy-credential/reset", gin.H{
		"password": "rdp-admin-pass-2",
	}, adminHeader)
	if resetResp.Code != http.StatusOK {
		t.Fatalf("self credential reset status=%d body=%s", resetResp.Code, resetResp.Body.String())
	}
	phase1AssertNoCredentialSecretLeak(t, resetResp.Body.String())
	if _, err := service.NewRDPProxyCredentialService(env.store, 8).Verify("admin", "rdp-admin-pass-1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("old self rdp password err=%v, want unauthorized", err)
	}
	if _, err := service.NewRDPProxyCredentialService(env.store, 8).Verify("admin", "rdp-admin-pass-2"); err != nil {
		t.Fatalf("new self rdp password verify err=%v", err)
	}

	disableResp := phase1Request(t, env.router, http.MethodDelete, "/api/v1/auth/rdp-proxy-credential", nil, adminHeader)
	if disableResp.Code != http.StatusOK {
		t.Fatalf("self credential disable status=%d body=%s", disableResp.Code, disableResp.Body.String())
	}
	disabled := phase1DecodeData[service.RDPProxyCredentialStatus](t, disableResp)
	if !disabled.Configured || disabled.Enabled || disabled.DisabledAt == nil {
		t.Fatalf("unexpected disabled self status: %#v", disabled)
	}

	operatorRole, err := env.store.GetRoleByName("operator")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := service.NewUserService(env.store, 8).Create(service.CreateUserInput{
		Username: "rdpoperator",
		Name:     "RDP Operator",
		Password: "operator123",
		RoleIDs:  []int64{operatorRole.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorToken := phase1Login(t, env.router, "rdpoperator", "operator123")
	operatorHeader := phase1AuthHeader(operatorToken)
	operatorSelf := phase1Request(t, env.router, http.MethodPut, "/api/v1/auth/rdp-proxy-credential", gin.H{
		"password": "operator-rdp-pass",
	}, operatorHeader)
	if operatorSelf.Code != http.StatusOK {
		t.Fatalf("operator self credential set status=%d body=%s", operatorSelf.Code, operatorSelf.Body.String())
	}
	operatorAdmin := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential", operator.ID), nil, operatorHeader)
	if operatorAdmin.Code != http.StatusForbidden {
		t.Fatalf("operator managed credential status=%d body=%s", operatorAdmin.Code, operatorAdmin.Body.String())
	}

	auditorRole, err := env.store.GetRoleByName("auditor")
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := service.NewUserService(env.store, 8).Create(service.CreateUserInput{
		Username: "rdpauditor",
		Name:     "RDP Auditor",
		Password: "auditor123",
		RoleIDs:  []int64{auditorRole.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	auditorToken := phase1Login(t, env.router, "rdpauditor", "auditor123")
	auditorAdmin := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential", auditor.ID), nil, phase1AuthHeader(auditorToken))
	if auditorAdmin.Code != http.StatusForbidden {
		t.Fatalf("auditor managed credential status=%d body=%s", auditorAdmin.Code, auditorAdmin.Body.String())
	}

	adminManagedStatus := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential", operator.ID), nil, adminHeader)
	if adminManagedStatus.Code != http.StatusOK {
		t.Fatalf("admin managed credential status=%d body=%s", adminManagedStatus.Code, adminManagedStatus.Body.String())
	}
	managed := phase1DecodeData[service.RDPProxyCredentialStatus](t, adminManagedStatus)
	if !managed.Configured || !managed.Enabled || managed.UserID != operator.ID {
		t.Fatalf("unexpected admin managed status: %#v", managed)
	}
	adminManagedSet := phase1Request(t, env.router, http.MethodPut, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential", operator.ID), gin.H{
		"password": "managed-rdp-pass-1",
	}, adminHeader)
	if adminManagedSet.Code != http.StatusOK {
		t.Fatalf("admin managed set status=%d body=%s", adminManagedSet.Code, adminManagedSet.Body.String())
	}
	phase1AssertNoCredentialSecretLeak(t, adminManagedSet.Body.String())
	if _, err := service.NewRDPProxyCredentialService(env.store, 8).Verify("rdpoperator", "managed-rdp-pass-1"); err != nil {
		t.Fatalf("managed set verify err=%v", err)
	}
	adminManagedReset := phase1Request(t, env.router, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential/reset", operator.ID), gin.H{
		"password": "managed-rdp-pass-2",
	}, adminHeader)
	if adminManagedReset.Code != http.StatusOK {
		t.Fatalf("admin managed reset status=%d body=%s", adminManagedReset.Code, adminManagedReset.Body.String())
	}
	if _, err := service.NewRDPProxyCredentialService(env.store, 8).Verify("rdpoperator", "managed-rdp-pass-1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("old managed rdp password err=%v, want unauthorized", err)
	}
	if _, err := service.NewRDPProxyCredentialService(env.store, 8).Verify("rdpoperator", "managed-rdp-pass-2"); err != nil {
		t.Fatalf("new managed rdp password verify err=%v", err)
	}
	adminManagedDisable := phase1Request(t, env.router, http.MethodDelete, fmt.Sprintf("/api/v1/users/%d/rdp-proxy-credential", operator.ID), nil, adminHeader)
	if adminManagedDisable.Code != http.StatusOK {
		t.Fatalf("admin managed disable status=%d body=%s", adminManagedDisable.Code, adminManagedDisable.Body.String())
	}
	managedDisabled := phase1DecodeData[service.RDPProxyCredentialStatus](t, adminManagedDisable)
	if managedDisabled.Enabled || managedDisabled.DisabledAt == nil {
		t.Fatalf("unexpected admin managed disabled status: %#v", managedDisabled)
	}
}

func TestPhase1UpdateRoleRenamesCasbinPolicies(t *testing.T) {
	env := newPhase1APITestEnv(t)
	adminToken := phase1Login(t, env.router, "admin", "admin123")
	adminHeader := phase1AuthHeader(adminToken)

	role, err := env.store.UpsertRole("ops_temp", "temporary operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.enforcer.AddPolicy("ops_temp", "/api/v1/assets", "GET|POST"); err != nil {
		t.Fatal(err)
	}
	if err := env.enforcer.SavePolicy(); err != nil {
		t.Fatal(err)
	}

	resp := phase1Request(t, env.router, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", role.ID), gin.H{
		"name":        "ops_renamed",
		"description": "renamed operator",
	}, adminHeader)
	if resp.Code != http.StatusOK {
		t.Fatalf("update role status=%d body=%s", resp.Code, resp.Body.String())
	}
	if policies, err := env.enforcer.GetFilteredPolicy(0, "ops_temp"); err != nil {
		t.Fatal(err)
	} else if len(policies) != 0 {
		t.Fatalf("old role policies should be removed: %#v", policies)
	}
	policies, err := env.enforcer.GetFilteredPolicy(0, "ops_renamed")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0][1] != "/api/v1/assets" || policies[0][2] != "GET|POST" {
		t.Fatalf("renamed role policies not preserved: %#v", policies)
	}
}

func TestPhase1DeleteRoleClearsCasbinPolicies(t *testing.T) {
	env := newPhase1APITestEnv(t)
	adminToken := phase1Login(t, env.router, "admin", "admin123")
	adminHeader := phase1AuthHeader(adminToken)

	role, err := env.store.UpsertRole("delete_temp", "temporary role")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.enforcer.AddPolicy("delete_temp", "/api/v1/assets", "GET"); err != nil {
		t.Fatal(err)
	}
	if err := env.enforcer.SavePolicy(); err != nil {
		t.Fatal(err)
	}

	resp := phase1Request(t, env.router, http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", role.ID), nil, adminHeader)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("delete role status=%d body=%s", resp.Code, resp.Body.String())
	}
	policies, err := env.enforcer.GetFilteredPolicy(0, "delete_temp")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatalf("deleted role policies should be removed: %#v", policies)
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

	active := true
	assetResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/assets", service.AssetInput{
		Name:       "phase1-linux",
		Address:    "10.0.0.10",
		PlatformID: phase1LinuxPlatformID(t, env.store),
		IsActive:   &active,
	}, adminHeader)
	if assetResp.Code != http.StatusCreated {
		t.Fatalf("create asset status=%d body=%s", assetResp.Code, assetResp.Body.String())
	}
	asset := phase1DecodeData[domain.Asset](t, assetResp)
	if asset.ID == 0 || asset.Address != "10.0.0.10" {
		t.Fatalf("unexpected asset: %#v", asset)
	}
	inactive := false
	inactiveResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/assets", service.AssetInput{
		Name:       "phase1-inactive",
		Address:    "10.0.0.11",
		PlatformID: phase1LinuxPlatformID(t, env.store),
		IsActive:   &inactive,
	}, adminHeader)
	if inactiveResp.Code != http.StatusCreated {
		t.Fatalf("create inactive asset status=%d body=%s", inactiveResp.Code, inactiveResp.Body.String())
	}
	inactiveAsset := phase1DecodeData[domain.Asset](t, inactiveResp)
	if inactiveAsset.IsActive {
		t.Fatalf("inactive asset should preserve explicit false: %#v", inactiveAsset)
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
	protocolsResp := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/platforms/%d/protocols", asset.PlatformID), nil, adminHeader)
	if protocolsResp.Code != http.StatusOK {
		t.Fatalf("platform protocols status=%d body=%s", protocolsResp.Code, protocolsResp.Body.String())
	}
	protocols := phase1DecodeData[[]domain.PlatformProtocol](t, protocolsResp)
	if len(protocols) == 0 || protocols[0].Name == "" || protocols[0].Port == 0 {
		t.Fatalf("unexpected platform protocols: %#v", protocols)
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
	dashboardResp := phase1Request(t, env.router, http.MethodGet, "/api/v1/dashboard/summary", nil, adminHeader)
	if dashboardResp.Code != http.StatusOK {
		t.Fatalf("dashboard summary status=%d body=%s", dashboardResp.Code, dashboardResp.Body.String())
	}
	dashboard := phase1DecodeData[struct {
		TotalAssets    int                     `json:"total_assets"`
		ActiveSessions int                     `json:"active_sessions"`
		TodaySessions  int                     `json:"today_sessions"`
		ActiveUsers    int                     `json:"active_users"`
		RecentSessions []domain.SessionSummary `json:"recent_sessions"`
	}](t, dashboardResp)
	if dashboard.TotalAssets < 2 || dashboard.ActiveSessions != 1 || dashboard.TodaySessions == 0 || dashboard.ActiveUsers != 1 || len(dashboard.RecentSessions) == 0 {
		t.Fatalf("unexpected dashboard summary: %#v", dashboard)
	}
	if dashboard.RecentSessions[0].AssetName != asset.Name || dashboard.RecentSessions[0].AccountName != account.Name {
		t.Fatalf("dashboard recent session missing names: %#v", dashboard.RecentSessions[0])
	}
	streamTokenResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/sessions/stream-token", nil, adminHeader)
	if streamTokenResp.Code != http.StatusCreated {
		t.Fatalf("stream token status=%d body=%s", streamTokenResp.Code, streamTokenResp.Body.String())
	}
	streamToken := phase1DecodeData[struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}](t, streamTokenResp)
	if streamToken.Token == "" || streamToken.ExpiresIn != 60 {
		t.Fatalf("unexpected stream token: %#v", streamToken)
	}
	legacyStreamAuth := phase1Request(t, env.router, http.MethodGet, "/api/v1/sessions/stream?access_token="+adminToken, nil, nil)
	if legacyStreamAuth.Code != http.StatusUnauthorized {
		t.Fatalf("stream should reject JWT query token status=%d body=%s", legacyStreamAuth.Code, legacyStreamAuth.Body.String())
	}
	tokenOnlyRole, err := env.store.UpsertRole("stream_token_only", "can mint stream token but cannot read sessions")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.enforcer.AddPolicy("stream_token_only", "/api/v1/sessions/stream-token", "POST"); err != nil {
		t.Fatal(err)
	}
	if err := env.enforcer.SavePolicy(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.NewUserService(env.store, 8).Create(service.CreateUserInput{
		Username: "streamer",
		Name:     "Stream Token Only",
		Password: "streamer123",
		RoleIDs:  []int64{tokenOnlyRole.ID},
	}); err != nil {
		t.Fatal(err)
	}
	streamerToken := phase1Login(t, env.router, "streamer", "streamer123")
	streamerStreamTokenResp := phase1Request(t, env.router, http.MethodPost, "/api/v1/sessions/stream-token", nil, phase1AuthHeader(streamerToken))
	if streamerStreamTokenResp.Code != http.StatusCreated {
		t.Fatalf("stream-token-only mint status=%d body=%s", streamerStreamTokenResp.Code, streamerStreamTokenResp.Body.String())
	}
	streamerStreamToken := phase1DecodeData[struct {
		Token string `json:"token"`
	}](t, streamerStreamTokenResp)
	forbiddenStream := phase1Request(t, env.router, http.MethodGet, "/api/v1/sessions/stream?stream_token="+streamerStreamToken.Token, nil, nil)
	if forbiddenStream.Code != http.StatusForbidden {
		t.Fatalf("stream token must still enforce sessions read permission, status=%d body=%s", forbiddenStream.Code, forbiddenStream.Body.String())
	}
	adminFinishResp := phase1Request(t, env.router, http.MethodPatch, fmt.Sprintf("/api/v1/sessions/%d", session.ID), gin.H{
		"is_finished": true,
	}, adminHeader)
	if adminFinishResp.Code != http.StatusNotFound {
		t.Fatalf("admin finish session status=%d body=%s", adminFinishResp.Code, adminFinishResp.Body.String())
	}
	recordingPath := filepath.Join(t.TempDir(), "phase1.cast")
	recordingDir := filepath.Dir(recordingPath)
	localRecordingSetting, err := env.store.GetSetting("recording.local.path")
	if err != nil {
		t.Fatal(err)
	}
	localRecordingSetting.Value = fmt.Sprintf("%q", recordingDir)
	if err := env.store.UpsertSetting(localRecordingSetting); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordingPath, []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	finishResp := phase1Request(t, env.router, http.MethodPatch, fmt.Sprintf("/api/v1/proxy/sessions/%d", session.ID), gin.H{
		"is_finished":    true,
		"recording_path": recordingPath,
	}, phase1ProxyHeader(env.cfg.ProxyAuth.Secret))
	if finishResp.Code != http.StatusOK {
		t.Fatalf("finish session status=%d body=%s", finishResp.Code, finishResp.Body.String())
	}
	finished := phase1DecodeData[domain.Session](t, finishResp)
	if !finished.IsFinished || finished.DateEnd == nil || finished.RecordingPath != recordingPath {
		t.Fatalf("session not finished: %#v", finished)
	}
	recordingResp := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/sessions/%d/recording", session.ID), nil, adminHeader)
	if recordingResp.Code != http.StatusOK {
		t.Fatalf("session recording status=%d body=%s", recordingResp.Code, recordingResp.Body.String())
	}
	recording := phase1DecodeData[struct {
		RecordingPath string `json:"recording_path"`
		DownloadURL   string `json:"download_url"`
		Available     bool   `json:"available"`
	}](t, recordingResp)
	if !recording.Available || recording.RecordingPath != recordingPath || !strings.Contains(recording.DownloadURL, "/recording?download=1") {
		t.Fatalf("unexpected recording metadata: %#v", recording)
	}
	downloadResp := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/sessions/%d/recording?download=1", session.ID), nil, adminHeader)
	if downloadResp.Code != http.StatusOK || !strings.Contains(downloadResp.Body.String(), `"version":2`) {
		t.Fatalf("recording download status=%d body=%s", downloadResp.Code, downloadResp.Body.String())
	}

	commandDetail := fmt.Sprintf(`{"session_id":%d,"sql":"select 1","rows_affected":1}`, session.ID)
	if err := env.store.Audit(&session.UserID, "db.query", "mysql", "127.0.0.1", commandDetail); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		noiseDetail := fmt.Sprintf(`{"session_id":%d,"sql":"select %d"}`, session.ID+1000, i)
		if err := env.store.Audit(&session.UserID, "db.query", "mysql", "127.0.0.1", noiseDetail); err != nil {
			t.Fatal(err)
		}
	}
	commandsResp := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/sessions/%d/commands", session.ID), nil, adminHeader)
	if commandsResp.Code != http.StatusOK {
		t.Fatalf("session commands status=%d body=%s", commandsResp.Code, commandsResp.Body.String())
	}
	commands := phase1DecodeData[[]domain.AuditLog](t, commandsResp)
	if len(commands) != 1 || commands[0].Detail != commandDetail {
		t.Fatalf("unexpected session commands: %#v", commands)
	}
	auditResp := phase1Request(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/audit-logs?search=select%%201&user_id=%d", session.UserID), nil, adminHeader)
	if auditResp.Code != http.StatusOK {
		t.Fatalf("audit logs status=%d body=%s", auditResp.Code, auditResp.Body.String())
	}
	auditPage := phase1DecodeData[struct {
		Items []domain.AuditLog `json:"items"`
		Total int               `json:"total"`
	}](t, auditResp)
	if auditPage.Total == 0 || len(auditPage.Items) == 0 {
		t.Fatalf("expected filtered audit logs, got %#v", auditPage)
	}
	forceResp := phase1Request(t, env.router, http.MethodPost, fmt.Sprintf("/api/v1/sessions/%d/force-finish", session.ID), nil, adminHeader)
	if forceResp.Code != http.StatusOK {
		t.Fatalf("force finish session status=%d body=%s", forceResp.Code, forceResp.Body.String())
	}
	forced := phase1DecodeData[domain.Session](t, forceResp)
	if !forced.IsFinished || forced.DateEnd == nil {
		t.Fatalf("session not force finished: %#v", forced)
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
	router   http.Handler
	store    *repository.Store
	cfg      config.Config
	enforcer *casbin.Enforcer
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
		Config:         cfg,
		Auth:           service.NewAuthService(store, jwtMgr, cfg),
		Users:          service.NewUserService(store, cfg.Security.PasswordMinLength),
		RDPCredentials: service.NewRDPProxyCredentialService(store, cfg.Security.PasswordMinLength),
		Assets:         service.NewAssetService(store, box),
		Permissions:    service.NewPermissionService(store),
		Tokens:         service.NewTokenService(store, box, cfg.ProxyAuth),
		Settings:       settings,
		Sessions:       service.NewSessionService(store),
		HostKeys:       service.NewHostKeyService(store),
		Store:          store,
		Enforcer:       enforcer,
	}
	return phase1APITestEnv{router: NewRouter(cfg, zap.NewNop(), db, h), store: store, cfg: cfg, enforcer: enforcer}
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

func phase1AssertNoCredentialSecretLeak(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{"password_hash", "rdp-admin-pass", "operator-rdp-pass", "managed-rdp-pass"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("credential response leaked %q in body: %s", forbidden, body)
		}
	}
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
