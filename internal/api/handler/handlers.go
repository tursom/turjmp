// Package handler 提供 HTTP API 请求处理器，将 Gin 路由映射到对应的业务服务层方法。
// Handler 结构体聚合了所有业务服务实例，每个公开方法对应一个 API 端点，负责请求参数提取、
// 业务逻辑调用和统一响应格式化。
package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
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
	// RDPCredentials 原生 RDP MITM 代理前端认证独立密码服务
	RDPCredentials *service.RDPProxyCredentialService
	// NativeRDP 原生 RDP MITM 代理的前端认证、授权和目标解析服务
	NativeRDP *service.NativeRDPResolverService
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

	streamMu     sync.Mutex
	streamTokens map[string]streamToken
}

type streamToken struct {
	Principal httpx.Principal
	ExpiresAt time.Time
}

type accessCheck struct {
	Key    string
	Object string
	Method string
}

var consoleAccessChecks = []accessCheck{
	{Key: "dashboard", Object: "/api/v1/dashboard/summary", Method: http.MethodGet},
	{Key: "assets", Object: "/api/v1/assets", Method: http.MethodGet},
	{Key: "asset_create", Object: "/api/v1/assets", Method: http.MethodPost},
	{Key: "asset_update", Object: "/api/v1/assets/:id", Method: http.MethodPut},
	{Key: "asset_delete", Object: "/api/v1/assets/:id", Method: http.MethodDelete},
	{Key: "accounts", Object: "/api/v1/assets/:id/accounts", Method: http.MethodGet},
	{Key: "account_create", Object: "/api/v1/assets/:id/accounts", Method: http.MethodPost},
	{Key: "account_update", Object: "/api/v1/assets/:id/accounts/:aid", Method: http.MethodPut},
	{Key: "account_delete", Object: "/api/v1/assets/:id/accounts/:aid", Method: http.MethodDelete},
	{Key: "platforms", Object: "/api/v1/platforms", Method: http.MethodGet},
	{Key: "platform_protocols", Object: "/api/v1/platforms/:id/protocols", Method: http.MethodGet},
	{Key: "platform_create", Object: "/api/v1/platforms", Method: http.MethodPost},
	{Key: "users", Object: "/api/v1/users", Method: http.MethodGet},
	{Key: "user_create", Object: "/api/v1/users", Method: http.MethodPost},
	{Key: "user_update", Object: "/api/v1/users/:id", Method: http.MethodPut},
	{Key: "user_delete", Object: "/api/v1/users/:id", Method: http.MethodDelete},
	{Key: "user_rdp_proxy_credential", Object: "/api/v1/users/:id/rdp-proxy-credential", Method: http.MethodGet},
	{Key: "roles", Object: "/api/v1/roles", Method: http.MethodGet},
	{Key: "role_create", Object: "/api/v1/roles", Method: http.MethodPost},
	{Key: "role_update", Object: "/api/v1/roles/:id", Method: http.MethodPut},
	{Key: "role_delete", Object: "/api/v1/roles/:id", Method: http.MethodDelete},
	{Key: "permissions", Object: "/api/v1/permissions", Method: http.MethodGet},
	{Key: "permission_create", Object: "/api/v1/permissions", Method: http.MethodPost},
	{Key: "permission_update", Object: "/api/v1/permissions/:id", Method: http.MethodPut},
	{Key: "permission_delete", Object: "/api/v1/permissions/:id", Method: http.MethodDelete},
	{Key: "sessions", Object: "/api/v1/sessions", Method: http.MethodGet},
	{Key: "session_force_finish", Object: "/api/v1/sessions/:id/force-finish", Method: http.MethodPost},
	{Key: "connection_tokens", Object: "/api/v1/authentication/connection-tokens/", Method: http.MethodPost},
	{Key: "audit_logs", Object: "/api/v1/audit-logs", Method: http.MethodGet},
	{Key: "settings", Object: "/api/v1/settings", Method: http.MethodGet},
	{Key: "setting_update", Object: "/api/v1/settings/:key", Method: http.MethodPut},
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

// Access returns the current user's effective console capabilities using Casbin policies.
func (h *Handler) Access(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	access := make(map[string]bool, len(consoleAccessChecks))
	for _, check := range consoleAccessChecks {
		access[check.Key] = h.isAllowed(principal, check.Object, check.Method)
	}
	httpx.JSON(c, 200, gin.H{"access": access})
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

// GetMyRDPProxyCredential 查询当前用户的原生 RDP 代理凭据状态。
func (h *Handler) GetMyRDPProxyCredential(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	status, err := h.RDPCredentials.Status(principal.UserID)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

// SetMyRDPProxyCredential 设置当前用户的原生 RDP 代理独立密码。
func (h *Handler) SetMyRDPProxyCredential(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	h.setRDPProxyCredential(c, principal.UserID)
}

// ResetMyRDPProxyCredential 覆盖当前用户的原生 RDP 代理独立密码并重新启用。
func (h *Handler) ResetMyRDPProxyCredential(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	h.resetRDPProxyCredential(c, principal.UserID)
}

// DisableMyRDPProxyCredential 禁用当前用户的原生 RDP 代理独立密码。
func (h *Handler) DisableMyRDPProxyCredential(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	status, err := h.RDPCredentials.Disable(principal.UserID)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

// GetUserRDPProxyCredential 查询指定用户的原生 RDP 代理凭据状态。
func (h *Handler) GetUserRDPProxyCredential(c *gin.Context) {
	status, err := h.RDPCredentials.Status(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

// SetUserRDPProxyCredential 设置指定用户的原生 RDP 代理独立密码。
func (h *Handler) SetUserRDPProxyCredential(c *gin.Context) {
	h.setRDPProxyCredential(c, pathID(c, "id"))
}

// ResetUserRDPProxyCredential 覆盖指定用户的原生 RDP 代理独立密码并重新启用。
func (h *Handler) ResetUserRDPProxyCredential(c *gin.Context) {
	h.resetRDPProxyCredential(c, pathID(c, "id"))
}

// DisableUserRDPProxyCredential 禁用指定用户的原生 RDP 代理独立密码。
func (h *Handler) DisableUserRDPProxyCredential(c *gin.Context) {
	status, err := h.RDPCredentials.Disable(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

func (h *Handler) setRDPProxyCredential(c *gin.Context, userID int64) {
	password, ok := bindRDPProxyCredentialPassword(c)
	if !ok {
		return
	}
	status, err := h.RDPCredentials.Set(userID, password)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

func (h *Handler) resetRDPProxyCredential(c *gin.Context, userID int64) {
	password, ok := bindRDPProxyCredentialPassword(c)
	if !ok {
		return
	}
	status, err := h.RDPCredentials.Reset(userID, password)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, status)
}

func bindRDPProxyCredentialPassword(c *gin.Context) (string, bool) {
	var req struct {
		Password string `json:"password"`
	}
	if !middleware.RequireJSON(c, &req) {
		return "", false
	}
	return req.Password, true
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

// ListUserGroups 查询所有用户组列表。
// 端点：GET /api/v1/user-groups（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListUserGroups(c *gin.Context) {
	groups, err := h.Store.ListUserGroups()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, groups)
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
	oldRole, err := h.Store.GetRole(role.ID)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if err := h.Store.UpdateRole(&role); err != nil {
		httpx.Error(c, err)
		return
	}
	if oldRole.Name != role.Name {
		if err := h.renameRolePolicies(oldRole.Name, role.Name); err != nil {
			_ = h.Store.UpdateRole(&oldRole)
			httpx.Error(c, err)
			return
		}
	}
	httpx.JSON(c, 200, role)
}

// renameRolePolicies keeps Casbin policies aligned when a role's display name
// changes, because role names are used as the policy subject.
func (h *Handler) renameRolePolicies(oldName, newName string) error {
	policies, err := h.Enforcer.GetFilteredPolicy(0, oldName)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	if _, err := h.Enforcer.RemoveFilteredPolicy(0, oldName); err != nil {
		return err
	}
	for _, policy := range policies {
		if len(policy) < 3 {
			continue
		}
		if _, err := h.Enforcer.AddPolicy(newName, policy[1], policy[2]); err != nil {
			_ = h.restoreRolePolicies(newName, oldName, policies)
			return err
		}
	}
	if err := h.Enforcer.SavePolicy(); err != nil {
		_ = h.restoreRolePolicies(newName, oldName, policies)
		return err
	}
	return nil
}

func (h *Handler) restoreRolePolicies(removeName, restoreName string, policies [][]string) error {
	_, _ = h.Enforcer.RemoveFilteredPolicy(0, removeName)
	for _, policy := range policies {
		if len(policy) < 3 {
			continue
		}
		if _, err := h.Enforcer.AddPolicy(restoreName, policy[1], policy[2]); err != nil {
			return err
		}
	}
	return h.Enforcer.SavePolicy()
}

func (h *Handler) clearRolePolicies(name string) error {
	if _, err := h.Enforcer.RemoveFilteredPolicy(0, name); err != nil {
		return err
	}
	return h.Enforcer.SavePolicy()
}

// DeleteRole 删除角色。若角色已被分配给用户，删除将失败。
// 端点：DELETE /api/v1/roles/:id（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DeleteRole(c *gin.Context) {
	role, err := h.Store.GetRole(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if err := h.Store.DeleteRole(role.ID); err != nil {
		httpx.Error(c, err)
		return
	}
	if err := h.clearRolePolicies(role.Name); err != nil {
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
	if _, err := h.Enforcer.RemoveFilteredPolicy(0, role.Name); err != nil {
		httpx.Error(c, err)
		return
	}
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

// ListPlatformProtocols 查询指定平台的协议端口配置。
// 端点：GET /api/v1/platforms/:id/protocols（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListPlatformProtocols(c *gin.Context) {
	protocols, err := h.Store.ListPlatformProtocols(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, protocols)
}

// CreatePlatform 创建或更新资产平台模板。
// 端点：POST /api/v1/platforms（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) CreatePlatform(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Protocol    string `json:"protocol"`
		Port        int    `json:"port"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Type) == "" {
		httpx.Error(c, domain.ErrInvalidArgument)
		return
	}
	platform, err := h.Store.UpsertPlatform(req.Name, req.Type, req.Description)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if strings.TrimSpace(req.Protocol) != "" {
		if req.Port <= 0 {
			httpx.Error(c, domain.ErrInvalidArgument)
			return
		}
		if err := h.Store.UpsertPlatformProtocol(platform.ID, req.Protocol, req.Port); err != nil {
			httpx.Error(c, err)
			return
		}
	}
	httpx.Created(c, platform)
}

// ListAssets 查询所有资产列表。
// 端点：GET /api/v1/assets（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListAssets(c *gin.Context) {
	assets, err := h.Assets.ListAssets()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	assets = filterAssets(assets, c)
	if c.Query("page") != "" || c.Query("per_page") != "" {
		page, perPage := queryPagination(c, 1, 20, 100)
		total := len(assets)
		start := (page - 1) * perPage
		if start > total {
			start = total
		}
		end := start + perPage
		if end > total {
			end = total
		}
		items := assets[start:end]
		if items == nil {
			items = []domain.AssetWithPlatform{}
		}
		httpx.JSON(c, 200, gin.H{
			"items":    items,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
		return
	}
	httpx.JSON(c, 200, assets)
}

// CreateAsset 创建新资产（服务器节点）。
// 端点：POST /api/v1/assets（需 JWT 认证 + RBAC 鉴权）
// 请求体包含资产名称、IP、端口、平台ID、资产组ID、描述等信息
func (h *Handler) CreateAsset(c *gin.Context) {
	var req service.AssetInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	created, err := h.Assets.CreateAsset(req)
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
//  1. bindSDKURLInput：根据请求方法绑定参数（GET 从查询字符串提取，POST 绑定 JSON 体）
//  2. MustPrincipal：从 JWT 中获取当前认证用户信息
//  3. proxy_host 为空时，默认使用请求的 Host/X-Forwarded-Host 头
//  4. BuildSDKURL：调用 TokenService 构造带签名 Token 的连接 URL，返回连接信息和可下载的文件内容
//
// 请求参数（GET 查询字符串）：
//
//	asset_id（必填）：目标资产 ID，正整数
//	account_id（必填）：SSH 账户 ID，正整数
//	protocol（可选）：连接协议，如 ssh、rdp，默认 ssh
//	connect_method（可选）：连接方式，如 direct、gateway
//	proxy_host（可选）：代理服务器地址，为空时自动使用请求的 Host 头
//	format（可选）：返回格式，如 json、rdp_file、ssh_config，默认 json
//
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
		RemoteAddr       string `json:"remote_addr"`
		ExpectedProtocol string `json:"expected_protocol"`
		Consume          *bool  `json:"consume"`
	}
	if !middleware.RequireJSON(c, &req) {
		return
	}
	consume := true
	if req.Consume != nil {
		consume = *req.Consume
	}
	result, err := h.Tokens.VerifyWithOptions(req.Token, c.GetHeader("X-Proxy-Auth"), c.ClientIP(), service.VerifyTokenOptions{
		ExpectedProtocol: req.ExpectedProtocol,
		Consume:          consume,
	})
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

// ProxyResolveNativeRDP validates mstsc front-side credentials and resolves the managed RDP target.
func (h *Handler) ProxyResolveNativeRDP(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	var req service.NativeRDPResolveInput
	if !middleware.RequireJSON(c, &req) {
		return
	}
	result, err := h.NativeRDP.Resolve(req)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, http.StatusOK, result)
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

// ProxyGetSession 供代理组件查询会话当前状态。
// 认证方式：通过 X-Proxy-Auth 请求头进行代理认证。
func (h *Handler) ProxyGetSession(c *gin.Context) {
	if !h.proxyAuthorized(c) {
		httpx.Error(c, domain.ErrUnauthorized)
		return
	}
	session, err := h.Sessions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, session)
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

// DashboardSummary 返回管理控制台仪表盘所需的聚合统计，避免前端拉取全量会话后自行聚合。
// 端点：GET /api/v1/dashboard/summary（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) DashboardSummary(c *gin.Context) {
	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	summary, err := h.Store.DashboardSummary(todayStart, 10)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, gin.H{
		"total_assets":    summary.TotalAssets,
		"active_sessions": summary.ActiveSessions,
		"today_sessions":  summary.TodaySessions,
		"active_users":    summary.ActiveUsers,
		"recent_sessions": summary.RecentSessions,
		"generated_at":    now,
	})
}

// IssueSessionStreamToken 签发短期一次性 WebSocket token，避免浏览器把 JWT access token 放进 URL。
// 端点：POST /api/v1/sessions/stream-token（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) IssueSessionStreamToken(c *gin.Context) {
	principal, err := httpx.MustPrincipal(c)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	token, err := newOpaqueToken()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	expiresAt := time.Now().UTC().Add(60 * time.Second)
	h.streamMu.Lock()
	if h.streamTokens == nil {
		h.streamTokens = make(map[string]streamToken)
	}
	for key, value := range h.streamTokens {
		if time.Now().UTC().After(value.ExpiresAt) {
			delete(h.streamTokens, key)
		}
	}
	h.streamTokens[token] = streamToken{Principal: principal, ExpiresAt: expiresAt}
	h.streamMu.Unlock()
	httpx.Created(c, gin.H{"token": token, "expires_at": expiresAt, "expires_in": 60})
}

// ListSessions 查询所有 SSH 会话记录列表。
// 端点：GET /api/v1/sessions（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListSessions(c *gin.Context) {
	sessions, err := h.Sessions.List()
	if err != nil {
		httpx.Error(c, err)
		return
	}
	sessions = filterSessions(sessions, c)
	httpx.JSON(c, 200, sessions)
}

// StreamSessions 通过 WebSocket 推送会话列表快照，供管理控制台实时刷新在线会话。
// 浏览器 WebSocket 无法设置 Authorization 头，因此前端需先用 /sessions/stream-token 换取短期一次性 stream_token。
func (h *Handler) StreamSessions(c *gin.Context) {
	if !h.authorizeWebSocket(c, "/api/v1/sessions", http.MethodGet) {
		return
	}
	conn, err := websocket.Accept(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx := c.Request.Context()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := h.writeSessionSnapshot(ctx, conn, c); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *Handler) writeSessionSnapshot(ctx context.Context, conn *websocket.Conn, c *gin.Context) error {
	sessions, err := h.Sessions.List()
	if err != nil {
		return err
	}
	sessions = filterSessions(sessions, c)
	return wsjson.Write(ctx, conn, gin.H{"type": "sessions", "sessions": sessions})
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

// SessionRecording returns a downloadable recording URL for a finished session.
// Local files are served back through this authenticated endpoint; remote URLs are returned as-is.
func (h *Handler) SessionRecording(c *gin.Context) {
	session, err := h.Sessions.Get(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	recordingPath := strings.TrimSpace(session.RecordingPath)
	if recordingPath == "" {
		httpx.Error(c, domain.ErrNotFound)
		return
	}
	if isRemoteRecordingURL(recordingPath) {
		if c.Query("download") == "1" {
			c.Redirect(http.StatusFound, recordingPath)
			return
		}
		httpx.JSON(c, http.StatusOK, gin.H{
			"recording_path": recordingPath,
			"url":            recordingPath,
			"download_url":   recordingPath,
			"available":      true,
		})
		return
	}
	if !h.isAllowedLocalRecordingPath(recordingPath) {
		httpx.JSON(c, http.StatusOK, gin.H{
			"recording_path": recordingPath,
			"url":            "",
			"download_url":   "",
			"available":      false,
		})
		return
	}
	info, err := os.Stat(recordingPath)
	if err != nil || info.IsDir() {
		httpx.JSON(c, http.StatusOK, gin.H{
			"recording_path": recordingPath,
			"url":            "",
			"download_url":   "",
			"available":      false,
		})
		return
	}
	downloadURL := "/api/v1/sessions/" + strconv.FormatInt(session.ID, 10) + "/recording?download=1"
	if c.Query("download") == "1" {
		c.FileAttachment(recordingPath, filepath.Base(recordingPath))
		return
	}
	httpx.JSON(c, http.StatusOK, gin.H{
		"recording_path": recordingPath,
		"url":            downloadURL,
		"download_url":   downloadURL,
		"available":      true,
	})
}

// ForceFinishSession 强制将会话标记为结束，并写入管理审计日志。
// 端点：POST /api/v1/sessions/:id/force-finish（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ForceFinishSession(c *gin.Context) {
	session, err := h.Sessions.ForceFinish(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if principal, err := httpx.MustPrincipal(c); err == nil {
		_ = h.Store.Audit(&principal.UserID, "session.force_finish", strconv.FormatInt(session.ID, 10), c.ClientIP(), "{}")
	}
	httpx.JSON(c, 200, session)
}

// ListSessionCommands 查询指定会话关联的命令/SQL审计记录。
// 端点：GET /api/v1/sessions/:id/commands（需 JWT 认证 + RBAC 鉴权）
func (h *Handler) ListSessionCommands(c *gin.Context) {
	logs, err := h.Store.ListSessionCommandLogs(pathID(c, "id"))
	if err != nil {
		httpx.Error(c, err)
		return
	}
	httpx.JSON(c, 200, logs)
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
	page, perPage := queryPagination(c, 1, 50, 500)
	logs, total, err := h.Store.ListAuditLogs(repository.AuditLogFilter{
		Search:   firstQuery(c, "q", "search"),
		UserID:   queryInt64OrZero(c.Query("user_id")),
		Action:   c.Query("action"),
		DateFrom: queryTime(c.Query("date_from"), false),
		DateTo:   queryTime(c.Query("date_to"), true),
		Limit:    perPage,
		Offset:   (page - 1) * perPage,
	})
	if err != nil {
		httpx.Error(c, err)
		return
	}
	if logs == nil {
		logs = []domain.AuditLog{}
	}
	httpx.JSON(c, 200, gin.H{
		"items":    logs,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

func (h *Handler) authorizeWebSocket(c *gin.Context, object, method string) bool {
	streamToken := strings.TrimSpace(c.Query("stream_token"))
	if streamToken != "" {
		principal, ok := h.consumeStreamToken(streamToken)
		if !ok {
			httpx.Error(c, domain.ErrUnauthorized)
			return false
		}
		return h.authorizePrincipal(c, principal, object, method)
	}
	rawToken := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if rawToken == "" {
		httpx.Error(c, domain.ErrUnauthorized)
		return false
	}
	claims, err := h.Auth.ParseAccessToken(rawToken)
	if err != nil {
		httpx.Error(c, domain.ErrUnauthorized)
		return false
	}
	principal := httpx.PrincipalFromClaims(claims)
	return h.authorizePrincipal(c, principal, object, method)
}

func (h *Handler) authorizePrincipal(c *gin.Context, principal httpx.Principal, object, method string) bool {
	if h.isAllowed(principal, object, method) {
		httpx.SetPrincipal(c, principal)
		return true
	}
	httpx.Error(c, domain.ErrForbidden)
	return false
}

func (h *Handler) isAllowed(principal httpx.Principal, object, method string) bool {
	subjects := append([]string{principal.Username}, principal.Roles...)
	for _, subject := range subjects {
		allowed, err := h.Enforcer.Enforce(subject, object, method)
		if err != nil {
			return false
		}
		if allowed {
			return true
		}
	}
	return false
}

func isRemoteRecordingURL(recordingPath string) bool {
	lower := strings.ToLower(recordingPath)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func (h *Handler) isAllowedLocalRecordingPath(recordingPath string) bool {
	allowedDirs := []string{h.Config.Proxy.RDP.RecordingDir()}
	if setting, err := h.Store.GetSetting("recording.local.path"); err == nil {
		allowedDirs = append(allowedDirs, settingStringValue(setting.Value))
	}
	recordingAbs, err := filepath.Abs(recordingPath)
	if err != nil {
		return false
	}
	recordingAbs = filepath.Clean(recordingAbs)
	for _, dir := range allowedDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dirAbs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		dirAbs = filepath.Clean(dirAbs)
		if recordingAbs == dirAbs || strings.HasPrefix(recordingAbs, dirAbs+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func settingStringValue(raw string) string {
	var decoded string
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
		return decoded
	}
	return strings.Trim(raw, `"`)
}

func (h *Handler) consumeStreamToken(token string) (httpx.Principal, bool) {
	h.streamMu.Lock()
	defer h.streamMu.Unlock()
	if h.streamTokens == nil {
		return httpx.Principal{}, false
	}
	value, ok := h.streamTokens[token]
	if !ok {
		return httpx.Principal{}, false
	}
	delete(h.streamTokens, token)
	if time.Now().UTC().After(value.ExpiresAt) {
		return httpx.Principal{}, false
	}
	return value.Principal, true
}

func newOpaqueToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
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

func filterAssets(assets []domain.AssetWithPlatform, c *gin.Context) []domain.AssetWithPlatform {
	query := strings.ToLower(strings.TrimSpace(firstQuery(c, "q", "search")))
	platformType := strings.ToLower(strings.TrimSpace(firstQuery(c, "platform_type", "protocol")))
	status := strings.ToLower(strings.TrimSpace(firstQuery(c, "status", "is_active")))
	if query == "" && platformType == "" && status == "" {
		return assets
	}
	filtered := assets[:0]
	for _, asset := range assets {
		if query != "" {
			name := strings.ToLower(asset.Name)
			address := strings.ToLower(asset.Address)
			if !strings.Contains(name, query) && !strings.Contains(address, query) {
				continue
			}
		}
		if platformType != "" && strings.ToLower(asset.PlatformType) != platformType {
			continue
		}
		if status != "" && status != "all" {
			wantActive := status == "active" || status == "true" || status == "1"
			wantInactive := status == "inactive" || status == "false" || status == "0"
			if (wantActive || wantInactive) && asset.IsActive != wantActive {
				continue
			}
		}
		filtered = append(filtered, asset)
	}
	return filtered
}

func filterSessions(sessions []domain.Session, c *gin.Context) []domain.Session {
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	query := strings.ToLower(strings.TrimSpace(firstQuery(c, "q", "search")))
	userID := queryInt64OrZero(c.Query("user_id"))
	assetID := queryInt64OrZero(c.Query("asset_id"))
	from := queryTime(c.Query("date_from"), false)
	to := queryTime(c.Query("date_to"), true)
	if status == "" && query == "" && userID == 0 && assetID == 0 && from == nil && to == nil {
		return sessions
	}
	filtered := sessions[:0]
	for _, session := range sessions {
		if status == "active" && session.IsFinished {
			continue
		}
		if status == "ended" && !session.IsFinished {
			continue
		}
		if userID != 0 && session.UserID != userID {
			continue
		}
		if assetID != 0 && session.AssetID != assetID {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{
				strconv.FormatInt(session.UserID, 10),
				strconv.FormatInt(session.AssetID, 10),
				strconv.FormatInt(session.AccountID, 10),
				session.Protocol,
				session.Type,
				session.LoginFrom,
				session.RemoteAddr,
			}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		if from != nil && session.DateStart.Before(*from) {
			continue
		}
		if to != nil && session.DateStart.After(*to) {
			continue
		}
		filtered = append(filtered, session)
	}
	return filtered
}

func firstQuery(c *gin.Context, keys ...string) string {
	for _, key := range keys {
		if value := c.Query(key); value != "" {
			return value
		}
	}
	return ""
}

func queryPagination(c *gin.Context, defaultPage, defaultPerPage, maxPerPage int) (int, int) {
	page := queryIntOrDefault(c.Query("page"), defaultPage)
	perPage := queryIntOrDefault(c.Query("per_page"), defaultPerPage)
	if page < 1 {
		page = defaultPage
	}
	if perPage < 1 {
		perPage = defaultPerPage
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	return page, perPage
}

func queryIntOrDefault(raw string, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func queryInt64OrZero(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func queryTime(raw string, endOfDay bool) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			if layout == "2006-01-02" {
				parsed = parsed.UTC()
				if endOfDay {
					parsed = parsed.Add(24*time.Hour - time.Nanosecond)
				}
			}
			return &parsed
		}
	}
	return nil
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
//  1. X-Forwarded-Host 请求头：优先使用反向代理传递的原始主机名
//  2. Request.Host：HTTP Host 头，作为回退值
//  3. 若值为逗号分隔的多主机列表（多级代理场景），取第一个值
//  4. 通过 net.SplitHostPort 剥离端口号，仅保留主机名部分
//  5. 移除 IPv6 地址两端的方括号（如 [::1] → ::1）
//
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
