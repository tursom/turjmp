// Package handler 提供 HTTP API 请求处理器，将 Gin 路由映射到对应的业务服务层方法。
// Handler 结构体聚合了所有业务服务实例，每个公开方法对应一个 API 端点，负责请求参数提取、
// 业务逻辑调用和统一响应格式化。
package handler

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/api/middleware"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
	"github.com/tursom/turjmp/internal/service"
)

// Handler 聚合所有业务服务实例和基础设施依赖，作为 HTTP 路由处理器的接收者。
// 每个公开方法对应一个 API 端点，通过 Gin 的 c *gin.Context 获取请求参数并返回响应。
type Handler struct {
	// Config 运行时配置：用于生成原生客户端连接信息中的代理端口和默认地址
	Config config.Config
	// Auth 认证服务：处理用户登录、登出、Token 刷新和 MFA 配置
	Auth *service.AuthService
	// Users 用户管理服务：处理用户的 CRUD 操作及角色关联
	Users *service.UserService
	// Assets 资产管理服务：处理资产、资产组和账户的 CRUD 操作及树形结构查询
	Assets *service.AssetService
	// Permissions 权限管理服务：处理权限规则的 CRUD 操作
	Permissions *service.PermissionService
	// Tokens 临时令牌服务：处理连接令牌的签发、验证和代理认证
	Tokens *service.TokenService
	// Settings 配置管理服务：处理系统级配置项的读写操作
	Settings *service.SettingService
	// Sessions 会话管理服务：处理 SSH 会话记录的 CRUD 操作
	Sessions *service.SessionService
	// HostKeys 管理 SSH 主机密钥的生成、存储和签名操作，供代理组件使用
	HostKeys *service.HostKeyService
	// Store 数据存储聚合：提供对数据库各表的直接读写操作
	Store *repository.Store
	// Enforcer Casbin 权限执行器：用于角色权限策略的管理和查询
	Enforcer *casbin.Enforcer
}

// Login 处理用户登录请求。
// 端点：POST /api/v1/auth/login（无需认证）
// 请求体：{username, password, mfa_code}，若用户未启用 MFA 则 mfa_code 可为空
// 成功返回 access_token 和 refresh_token
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

// Refresh 使用 refresh_token 刷新 access_token。
// 端点：POST /api/v1/auth/refresh（无需认证）
// 请求体：{refresh_token}，成功返回新的 access_token 和 refresh_token
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

// Logout 处理用户登出请求，撤销当前用户的所有 refresh_token。
// 端点：POST /api/v1/auth/logout（需 JWT 认证）
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

// MFASetup 为当前登录用户初始化 MFA（多因素认证），生成 TOTP 密钥和二维码信息。
// 端点：POST /api/v1/auth/mfa/setup（需 JWT 认证）
// 返回 setup 信息包含 secret 和二维码 URL
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

// MFAVerify 验证 TOTP 验证码，完成 MFA 绑定。
// 端点：POST /api/v1/auth/mfa/verify（需 JWT 认证）
// 请求体：{code}，验证成功后用户登录即需提供 MFA 验证码
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

// ListUsers 查询所有用户列表。
// 端点：GET /api/v1/users（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListUsers(c *gin.Context) {
	users, err := h.Users.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, users)
}

// CreateUser 创建新用户。
// 端点：POST /api/v1/users（需 JWT 认证 + RBAC 鉴权）
// 请求体：{username, password, roles}
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

// GetUser 根据 ID 查询单个用户及其关联角色。
// 端点：GET /api/v1/users/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) GetUser(c *gin.Context) {
	user, roles, err := h.Users.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{"user": user, "roles": roles})
}

// UpdateUser 更新指定用户的信息（用户名、密码、角色等）。
// 端点：PUT /api/v1/users/:id（需 JWT 认证 + RBAC 鉴权）
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

// DeleteUser 删除指定用户。
// 端点：DELETE /api/v1/users/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeleteUser(c *gin.Context) {
	if err := h.Users.Delete(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

// ListRoles 查询所有角色列表。
// 端点：GET /api/v1/roles（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.Store.ListRoles()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, roles)
}

// CreateRole 创建新角色。
// 端点：POST /api/v1/roles（需 JWT 认证 + RBAC 鉴权）
// 请求体：{name}
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

// GetRole 根据 ID 查询角色信息及其关联的 Casbin 权限策略。
// 端点：GET /api/v1/roles/:id（需 JWT 认证 + RBAC 鉴权）
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

// UpdateRole 更新角色名称。
// 端点：PUT /api/v1/roles/:id（需 JWT 认证 + RBAC 鉴权）
// 请求体：{name}
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

// DeleteRole 删除角色。若角色已被分配给用户，删除将失败。
// 端点：DELETE /api/v1/roles/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeleteRole(c *gin.Context) {
	if err := h.Store.DeleteRole(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

// SetRolePermissions 为指定角色设置 Casbin 权限策略。先清除该角色的所有旧策略，再写入新策略。
// 端点：POST /api/v1/roles/:id/permissions（需 JWT 认证 + RBAC 鉴权）
// 请求体：{permissions: [{path, method}]}，成功后返回更新后的策略列表
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

// ListPlatforms 查询所有资产平台列表（如 Linux、Windows 等）。
// 端点：GET /api/v1/platforms（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListPlatforms(c *gin.Context) {
	platforms, err := h.Assets.ListPlatforms()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, platforms)
}

// ListAssets 查询所有资产列表。
// 端点：GET /api/v1/assets（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListAssets(c *gin.Context) {
	assets, err := h.Assets.ListAssets()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, assets)
}

// CreateAsset 创建新资产（服务器节点）。
// 端点：POST /api/v1/assets（需 JWT 认证 + RBAC 鉴权）
// 请求体包含资产名称、IP、端口、平台ID、资产组ID、描述等信息
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

// GetAsset 根据 ID 查询单个资产详情。
// 端点：GET /api/v1/assets/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) GetAsset(c *gin.Context) {
	asset, err := h.Assets.GetAsset(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, asset)
}

// UpdateAsset 更新指定资产的信息。
// 端点：PUT /api/v1/assets/:id（需 JWT 认证 + RBAC 鉴权）
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

// DeleteAsset 删除指定资产及其关联的账户信息。
// 端点：DELETE /api/v1/assets/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeleteAsset(c *gin.Context) {
	if err := h.Assets.DeleteAsset(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

// AssetTree 查询资产树状结构，按资产组层次组织所有资产。
// 端点：GET /api/v1/assets/tree（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) AssetTree(c *gin.Context) {
	tree, err := h.Assets.Tree()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, tree)
}

// ListAccounts 查询指定资产下的所有 SSH 账户。
// 端点：GET /api/v1/assets/:id/accounts（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListAccounts(c *gin.Context) {
	accounts, err := h.Assets.ListAccounts(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, accounts)
}

// CreateAccount 为指定资产创建 SSH 账户（含用户名、密码/密钥等信息）。
// 端点：POST /api/v1/assets/:id/accounts（需 JWT 认证 + RBAC 鉴权）
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

// GetAccount 查询指定资产的指定账户详情（敏感字段 secret、passphrase 已脱敏）。
// 端点：GET /api/v1/assets/:id/accounts/:aid（需 JWT 认证 + RBAC 鉴权）
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

// UpdateAccount 更新指定资产的指定账户信息。
// 端点：PUT /api/v1/assets/:id/accounts/:aid（需 JWT 认证 + RBAC 鉴权）
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

// DeleteAccount 删除指定资产的指定账户。
// 端点：DELETE /api/v1/assets/:id/accounts/:aid（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeleteAccount(c *gin.Context) {
	if err := h.Assets.DeleteAccount(pathID(c, "id"), pathID(c, "aid")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

// ListPermissions 查询所有权限规则列表。
// 端点：GET /api/v1/permissions（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListPermissions(c *gin.Context) {
	permissions, err := h.Permissions.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, permissions)
}

// CreatePermission 创建新的权限规则（关联用户/角色到资产/账户）。
// 端点：POST /api/v1/permissions（需 JWT 认证 + RBAC 鉴权）
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

// GetPermission 查询指定权限规则及其关联的资源授权链路。
// 端点：GET /api/v1/permissions/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) GetPermission(c *gin.Context) {
	permission, links, err := h.Permissions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{"permission": permission, "links": links})
}

// UpdatePermission 更新指定权限规则。
// 端点：PUT /api/v1/permissions/:id（需 JWT 认证 + RBAC 鉴权）
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

// DeletePermission 删除指定权限规则。
// 端点：DELETE /api/v1/permissions/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeletePermission(c *gin.Context) {
	if err := h.Permissions.Delete(pathID(c, "id")); err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.NoContent(c)
}

// IssueConnectionToken 为当前用户签发一次性 SSH 连接令牌，用于代理组件验证连接请求。
// 端点：POST /api/v1/authentication/connection-tokens/（需 JWT 认证 + RBAC 鉴权）
// 请求体：{asset_id, account_id}，令牌有效期 5 分钟
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

// SDKConnectionToken 为原生客户端生成连接 URL 和连接令牌，供 SDK 或命令行工具使用。
// 端点：GET/POST /api/v1/authentication/connection-tokens/sdk-url（需 JWT 认证 + RBAC 鉴权）
// GET 方法：参数通过 URL 查询字符串传递，适合浏览器直接打开下载链接
// POST 方法：参数通过 JSON 请求体传递，支持更丰富的连接配置
// 请求流程：
//   1. bindSDKURLInput：根据请求方法绑定参数（GET 从查询字符串提取，POST 绑定 JSON 体）
//   2. MustPrincipal：从 JWT 中获取当前认证用户信息
//   3. proxy_host 为空时，默认使用请求的 Host/X-Forwarded-Host 头
//   4. BuildSDKURL：调用 TokenService 构造带签名 Token 的连接 URL，返回连接信息和可下载的文件内容
// 请求参数（GET 查询字符串）：
//   asset_id（必填）：目标资产 ID，正整数
//   account_id（必填）：SSH 账户 ID，正整数
//   protocol（可选）：连接协议，如 ssh、rdp，默认 ssh
//   connect_method（可选）：连接方式，如 direct、gateway
//   proxy_host（可选）：代理服务器地址，为空时自动使用请求的 Host 头
//   format（可选）：返回格式，如 json、rdp_file、ssh_config，默认 json
// 响应体包含 token、expires_at、url 和可选的连接文件内容
func (h *Handler) SDKConnectionToken(c *gin.Context) {
	req, ok := bindSDKURLInput(c)
	if !ok {
		return
	}
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if req.ProxyHost == "" {
		req.ProxyHost = requestProxyHost(c)
	}
	result, err := h.Tokens.BuildSDKURL(principal.UserID, req, h.Config.Proxy)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.Created(c, result)
}

// VerifyConnectionToken 供 SSH 代理组件调用，验证连接令牌的有效性
// 该接口通过 X-Proxy-Auth 请求头进行代理认证
// 请求体包含连接令牌和发起连接的真实客户端 IP（remote_addr）
func (h *Handler) VerifyConnectionToken(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
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

// ListSessions 查询所有 SSH 会话记录列表。
// 端点：GET /api/v1/sessions（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListSessions(c *gin.Context) {
	sessions, err := h.Sessions.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, sessions)
}

// CreateSession 创建新的 SSH 会话记录。
// 端点：POST /api/v1/sessions（需 JWT 认证 + RBAC 鉴权）
// 请求体：{user_id, username, asset_id, asset_name, account_id, protocol, host, port, remote_addr}
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

// GetSession 查询指定会话记录的详细信息。
// 端点：GET /api/v1/sessions/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) GetSession(c *gin.Context) {
	session, err := h.Sessions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, session)
}

// UpdateSession 更新会话记录（标记结束状态、录像路径等）。
// 端点：PATCH /api/v1/sessions/:id（需 JWT 认证 + RBAC 鉴权）
// 请求体：{is_finished, recording_path}
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

// ListSettings 查询所有系统配置项列表。
// 端点：GET /api/v1/settings（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListSettings(c *gin.Context) {
	settings, err := h.Settings.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, settings)
}

// GetSetting 根据 key 查询单个系统配置项的值。
// 端点：GET /api/v1/settings/:key（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) GetSetting(c *gin.Context) {
	setting, err := h.Settings.Get(c.Param("key"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, setting)
}

// UpdateSetting 更新指定 key 的系统配置项。
// 端点：PUT /api/v1/settings/:key（需 JWT 认证 + RBAC 鉴权）
// 请求体：{value}
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

// ListAuditLogs 查询所有审计日志记录。
// 端点：GET /api/v1/audit-logs（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListAuditLogs(c *gin.Context) {
	logs, err := h.Store.ListAuditLogs()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, logs)
}

// pathID 从 Gin 路径参数中提取名为 name 的整数值（int64），解析失败时返回 0。
// 用作 Handler 中从 URL 路径（如 /api/v1/users/:id）提取 ID 参数的辅助函数。
func pathID(c *gin.Context, name string) int64 {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// bindSDKURLInput 根据 HTTP 请求方法绑定 SDK URL 输入参数，支持 GET 和 POST 两种方式。
// POST 请求：通过 middleware.RequireJSON 从 JSON 请求体绑定完整的 SDKURLInput 结构
// GET 请求：从 URL 查询字符串中提取各字段，asset_id 和 account_id 为必填参数，须为有效正整数
func bindSDKURLInput(c *gin.Context) (service.SDKURLInput, bool) {
	var req service.SDKURLInput
	if c.Request.Method != http.MethodGet {
		return req, middleware.RequireJSON(c, &req)
	}
	query := c.Request.URL.Query()
	assetID, ok := queryInt64(c, query.Get("asset_id"))
	if !ok {
		return req, false
	}
	accountID, ok := queryInt64(c, query.Get("account_id"))
	if !ok {
		return req, false
	}
	req.AssetID = assetID
	req.AccountID = accountID
	req.Protocol = query.Get("protocol")
	req.ConnectMethod = query.Get("connect_method")
	req.ProxyHost = query.Get("proxy_host")
	req.Format = query.Get("format")
	return req, true
}

// queryInt64 从查询字符串参数中解析 int64 值，用于 GET 请求参数提取。
// 解析规则：
//   - 空字符串：返回 (0, false) 并写入错误响应
//   - 非数字输入：返回 (0, false) 并写入错误响应
//   - 值 ≤ 0：返回 (0, false) 并写入错误响应（asset_id 和 account_id 须为正整数）
//   - 合法正整数：返回 (n, true)
func queryInt64(c *gin.Context, raw string) (int64, bool) {
	if strings.TrimSpace(raw) == "" {
		httpx.Error(c, domain.ErrInvalidArgument)
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		httpx.Error(c, domain.ErrInvalidArgument)
		return 0, false
	}
	return n, true
}

// requestProxyHost 从 HTTP 请求中解析代理主机地址，按优先级依次尝试多种来源。
// 解析链路：
//   1. X-Forwarded-Host 请求头：优先使用反向代理传递的原始主机名
//   2. Request.Host：HTTP Host 头，作为回退值
//   3. 若值为逗号分隔的多主机列表（多级代理场景），取第一个值
//   4. 通过 net.SplitHostPort 剥离端口号，仅保留主机名部分
//   5. 移除 IPv6 地址两端的方括号（如 [::1] → ::1）
// 返回值不含端口号的纯主机名或 IP 地址
func requestProxyHost(c *gin.Context) string {
	host := strings.TrimSpace(c.GetHeader("X-Forwarded-Host"))
	if host == "" {
		host = c.Request.Host
	}
	if strings.Contains(host, ",") {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil && parsedHost != "" {
		return parsedHost
	}
	return strings.Trim(host, "[]")
}

// proxyAuthorized 校验代理请求的合法性
// 从 X-Proxy-Auth 请求头提取代理密钥，结合客户端 IP 进行双重验证
// 返回 true 表示该请求来自合法的代理组件
func (h *Handler) proxyAuthorized(c *gin.Context) bool {
	return h.Tokens.AuthorizeProxy(c.GetHeader("X-Proxy-Auth"), c.ClientIP())
}
