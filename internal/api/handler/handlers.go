package handler

import (
	"strconv"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/api/middleware"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
	"github.com/tursom/turjmp/internal/service"
)

type Handler struct {
	Auth        *service.AuthService
	Users       *service.UserService
	Assets      *service.AssetService
	Permissions *service.PermissionService
	Tokens      *service.TokenService
	Settings    *service.SettingService
	Sessions    *service.SessionService
	// HostKeys 管理 SSH 主机密钥的生成、存储和签名操作，供代理组件使用
	HostKeys    *service.HostKeyService
	Store       *repository.Store
	Enforcer    *casbin.Enforcer
}

func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	result, err := h.Auth.Login(req.Username, req.Password, req.MFACode)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, result)
}

func (h *Handler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	result, err := h.Auth.Refresh(req.RefreshToken)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, result)
}

func (h *Handler) Logout(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if err := h.Auth.Logout(principal.UserID); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) MFASetup(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	setup, err := h.Auth.SetupMFA(principal.UserID)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, setup)
}

func (h *Handler) MFAVerify(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if err := h.Auth.VerifyMFA(principal.UserID, req.Code); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) ListUsers(c *gin.Context) {
	users, err := h.Users.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, users)
}

func (h *Handler) CreateUser(c *gin.Context) {
	var req service.CreateUserInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	user, err := h.Users.Create(req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, user)
}

func (h *Handler) GetUser(c *gin.Context) {
	user, roles, err := h.Users.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{"user": user, "roles": roles})
}

func (h *Handler) UpdateUser(c *gin.Context) {
	var req service.UpdateUserInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	user, err := h.Users.Update(pathID(c, "id"), req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, user)
}

func (h *Handler) DeleteUser(c *gin.Context) {
	if err := h.Users.Delete(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.Store.ListRoles()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, roles)
}

func (h *Handler) CreateRole(c *gin.Context) {
	var role domain.Role
	if !middleware.RequireJSON(c, &role) {
		return
	}
	if err := h.Store.CreateRole(&role); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, role)
}

func (h *Handler) GetRole(c *gin.Context) {
	role, err := h.Store.GetRole(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	policies, err := h.Enforcer.GetFilteredPolicy(0, role.Name)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{"role": role, "permissions": policies})
}

func (h *Handler) UpdateRole(c *gin.Context) {
	var role domain.Role
	if !middleware.RequireJSON(c, &role) {
		return
	}
	role.ID = pathID(c, "id")
	if err := h.Store.UpdateRole(&role); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, role)
}

func (h *Handler) DeleteRole(c *gin.Context) {
	if err := h.Store.DeleteRole(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) SetRolePermissions(c *gin.Context) {
	role, err := h.Store.GetRole(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	var req struct {
		Permissions []struct {
			Path   string `json:"path"`
			Method string `json:"method"`
		} `json:"permissions"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	_, _ = h.Enforcer.RemoveFilteredPolicy(0, role.Name)
	for _, permission := range req.Permissions {
		if _, err := h.Enforcer.AddPolicy(role.Name, permission.Path, permission.Method); err != nil {
			httpx.Error(c, err)
			return
		}
	}
	if err := h.Enforcer.SavePolicy(); err != nil {
		httpx.Error(c, err)
		return
	}
	policies, err := h.Enforcer.GetFilteredPolicy(0, role.Name)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, policies)
}

func (h *Handler) ListPlatforms(c *gin.Context) {
	platforms, err := h.Assets.ListPlatforms()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, platforms)
}

func (h *Handler) ListAssets(c *gin.Context) {
	assets, err := h.Assets.ListAssets()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, assets)
}

func (h *Handler) CreateAsset(c *gin.Context) {
	var asset domain.Asset
	if !middleware.RequireJSON(c, &asset) {
		return
	}
	created, err := h.Assets.CreateAsset(asset)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, created)
}

func (h *Handler) GetAsset(c *gin.Context) {
	asset, err := h.Assets.GetAsset(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, asset)
}

func (h *Handler) UpdateAsset(c *gin.Context) {
	var asset domain.Asset
	if !middleware.RequireJSON(c, &asset) {
		return
	}
	updated, err := h.Assets.UpdateAsset(pathID(c, "id"), asset)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, updated)
}

func (h *Handler) DeleteAsset(c *gin.Context) {
	if err := h.Assets.DeleteAsset(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) AssetTree(c *gin.Context) {
	tree, err := h.Assets.Tree()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, tree)
}

func (h *Handler) ListAccounts(c *gin.Context) {
	accounts, err := h.Assets.ListAccounts(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, accounts)
}

func (h *Handler) CreateAccount(c *gin.Context) {
	var req service.AccountInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	account, err := h.Assets.CreateAccount(pathID(c, "id"), req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, account)
}

func (h *Handler) GetAccount(c *gin.Context) {
	account, err := h.Store.GetAssetAccount(pathID(c, "id"), pathID(c, "aid"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	account.Secret = ""
	account.Passphrase = ""
	httpx.JSON(c, 200, account)
}

func (h *Handler) UpdateAccount(c *gin.Context) {
	var req service.AccountInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	account, err := h.Assets.UpdateAccount(pathID(c, "id"), pathID(c, "aid"), req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, account)
}

func (h *Handler) DeleteAccount(c *gin.Context) {
	if err := h.Assets.DeleteAccount(pathID(c, "id"), pathID(c, "aid")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) ListPermissions(c *gin.Context) {
	permissions, err := h.Permissions.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, permissions)
}

func (h *Handler) CreatePermission(c *gin.Context) {
	var req service.PermissionInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	permission, err := h.Permissions.Create(req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, permission)
}

func (h *Handler) GetPermission(c *gin.Context) {
	permission, links, err := h.Permissions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{"permission": permission, "links": links})
}

func (h *Handler) UpdatePermission(c *gin.Context) {
	var req service.PermissionInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	permission, err := h.Permissions.Update(pathID(c, "id"), req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, permission)
}

func (h *Handler) DeletePermission(c *gin.Context) {
	if err := h.Permissions.Delete(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) IssueConnectionToken(c *gin.Context) {
	var req service.IssueTokenInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	token, err := h.Tokens.Issue(principal.UserID, req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, gin.H{"token": token.Value, "expires_at": token.ExpiresAt, "expires_in": 300})
}

// VerifyConnectionToken 供 SSH 代理组件调用，验证连接令牌的有效性
// 该接口通过 X-Proxy-Auth 请求头进行代理认证
// 请求体包含连接令牌和发起连接的真实客户端 IP（remote_addr）
func (h *Handler) VerifyConnectionToken(c *gin.Context) {
	var req struct {
		Token      string `json:"token"`
		// RemoteAddr 发起 SSH 连接的真实客户端地址，用于审计和 IP 白名单校验
		RemoteAddr string `json:"remote_addr"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	result, err := h.Tokens.Verify(req.Token, c.GetHeader("X-Proxy-Auth"), c.ClientIP())
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, result)
}

// SSHFingerprint 返回所有 SSH 主机密钥的指纹信息（公钥摘要）
// 需要 JWT 认证和 RBAC 权限校验（secure 路由组）
// 返回每个密钥的算法、SHA256 指纹和公钥字符串
func (h *Handler) SSHFingerprint(c *gin.Context) {
	keys, err := h.HostKeys.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	out := make([]gin.H, 0, len(keys))
	for _, key := range keys {
		out = append(out, gin.H{
			"algorithm":   key.Algorithm,
			"fingerprint": key.Fingerprint,
			"public_key":  key.PublicKey,
		})
	}
	httpx.JSON(c, 200, out)
}

// ProxyHostKeys 供代理组件获取所有 SSH 主机密钥（含私钥），用于代理服务器建立 SSH 连接
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证（proxyAuthorized）
// 与 SSHFingerprint 不同，此接口返回完整的私钥信息，仅限内部代理使用
func (h *Handler) ProxyHostKeys(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	keys, err := h.HostKeys.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	out := make([]gin.H, 0, len(keys))
	for _, key := range keys {
		out = append(out, gin.H{
			"algorithm":   key.Algorithm,
			"fingerprint": key.Fingerprint,
			"private_key": key.PrivateKey,
			"public_key":  key.PublicKey,
		})
	}
	httpx.JSON(c, 200, out)
}

// ProxyCreateSession 供代理组件创建 SSH 会话记录
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证
// 请求体为 domain.Session 结构，包含用户、资产、账户、协议等会话元数据
func (h *Handler) ProxyCreateSession(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	var sess domain.Session
	if !middleware.RequireJSON(c, &sess) {
		return
	}
	created, err := h.Sessions.Create(sess)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, created)
}

// ProxyUpdateSession 供代理组件更新 SSH 会话状态（结束标记、录像路径）
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证
// 请求参数：路径参数 id（会话ID），请求体 is_finished（是否结束）、recording_path（录像文件路径）
func (h *Handler) ProxyUpdateSession(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	var req struct {
		IsFinished    bool   `json:"is_finished"`
		RecordingPath string `json:"recording_path"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	session, err := h.Sessions.Update(pathID(c, "id"), req.IsFinished, req.RecordingPath)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, session)
}

// ProxyGetSetting 供代理组件获取指定 key 的系统配置项
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证
// 路径参数 key 对应 settings 表中的配置键名
func (h *Handler) ProxyGetSetting(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	setting, err := h.Store.GetSetting(c.Param("key"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, setting)
}

// ProxyCommandFilterACLs 供代理组件获取命令过滤规则列表
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证
// 返回所有 command_filter_acls 表中的 ACL 规则，代理组件使用这些规则拦截/放行用户执行的命令
func (h *Handler) ProxyCommandFilterACLs(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	rules, err := h.Store.ListCommandFilterACLs()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, rules)
}

// ProxyCreateAuditLog 供代理组件写入审计日志
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证
// 请求体包含：user_id（操作用户ID，可为空）、action（操作类型）、resource（资源标识）、remote_addr（客户端地址）、detail（详细信息）
// 该接口用于代理组件记录用户通过跳板机执行的操作行为
func (h *Handler) ProxyCreateAuditLog(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	var req struct {
		UserID     *int64 `json:"user_id"`
		Action     string `json:"action"`
		Resource   string `json:"resource"`
		RemoteAddr string `json:"remote_addr"`
		Detail     string `json:"detail"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	if err := h.Store.Audit(req.UserID, req.Action, req.Resource, req.RemoteAddr, req.Detail); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

func (h *Handler) ListSessions(c *gin.Context) {
	sessions, err := h.Sessions.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, sessions)
}

func (h *Handler) CreateSession(c *gin.Context) {
	var sess domain.Session
	if !middleware.RequireJSON(c, &sess) {
		return
	}
	created, err := h.Sessions.Create(sess)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, created)
}

func (h *Handler) GetSession(c *gin.Context) {
	session, err := h.Sessions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, session)
}

func (h *Handler) UpdateSession(c *gin.Context) {
	var req struct {
		IsFinished    bool   `json:"is_finished"`
		RecordingPath string `json:"recording_path"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	session, err := h.Sessions.Update(pathID(c, "id"), req.IsFinished, req.RecordingPath)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, session)
}

func (h *Handler) ListSettings(c *gin.Context) {
	settings, err := h.Settings.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, settings)
}

func (h *Handler) GetSetting(c *gin.Context) {
	setting, err := h.Settings.Get(c.Param("key"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, setting)
}

func (h *Handler) UpdateSetting(c *gin.Context) {
	var req struct {
		Value string `json:"value"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	setting, err := h.Settings.Update(c.Param("key"), req.Value)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, setting)
}

func (h *Handler) ListAuditLogs(c *gin.Context) {
	logs, err := h.Store.ListAuditLogs()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, logs)
}

func pathID(c *gin.Context, name string) int64 {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// proxyAuthorized 校验代理请求的合法性
// 从 X-Proxy-Auth 请求头提取代理密钥，结合客户端 IP 进行双重验证
// 返回 true 表示该请求来自合法的代理组件
func (h *Handler) proxyAuthorized(c *gin.Context) bool {
	return h.Tokens.AuthorizeProxy(c.GetHeader("X-Proxy-Auth"), c.ClientIP())
}
