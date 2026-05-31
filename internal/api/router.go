// Package api 提供 Turjmp SSH 跳板机的 HTTP API 路由注册和中间件编排。
// 路由采用分组设计：公开路由（健康检查、登录、代理接口）、JWT 认证路由和 JWT+RBAC 鉴权路由。
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/api/middleware"
	"github.com/tursom/turjmp/internal/config"
	// dbproxy 数据库代理服务实现，封装 MySQL 协议代理和 Web DB 终端功能
	dbproxy "github.com/tursom/turjmp/internal/proxy/db"
	sshproxy "github.com/tursom/turjmp/internal/proxy/ssh"
	"github.com/tursom/turjmp/internal/repository"
)

// NewRouter 创建并配置 Gin 路由引擎，注册全局中间件、健康检查端点、Prometheus指标端点、
// 公开 API（登录/刷新/代理）、JWT认证端点（登出/MFA）和 JWT+RBAC 安全端点（用户/角色/资产/权限/会话/配置/审计）。
// cfg 为应用配置，log 为日志实例，db 为数据库连接，h 为聚合了所有业务服务的 Handler 实例。
func NewRouter(cfg config.Config, log *zap.Logger, db *repository.DB, h *handler.Handler) *gin.Engine {
	if cfg.App.Environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	// 全局中间件链：Recovery → Metrics → RateLimit → RequestLogger
	r.Use(gin.Recovery())
	r.Use(middleware.Metrics())
	r.Use(middleware.RateLimit(cfg.RateLimit))
	r.Use(requestLogger(log))

	// 公开路由组（无需认证）
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	// WebSocket 终端路由：浏览器通过 WebSocket 协议直连 SSH 代理，实现 Web 终端功能
	r.GET("/ws/terminal", gin.WrapH(sshproxy.NewWebTerminal(cfg)))
	// WebSocket 数据库终端：通过 usql 子进程连接 MySQL/PostgreSQL 目标资产。
	r.GET("/ws/db-terminal", gin.WrapH(dbproxy.NewWebTerminal(cfg)))
	// /health/ready：就绪检查端点，验证数据库连接可用性（无需认证）
	r.GET("/health/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	// /metrics：Prometheus 指标采集端点，由 promhttp 暴露（无需认证）
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// v1：API 版本 1 路由组，挂载于 /api/v1
	v1 := r.Group("/api/v1")
	// 公开认证路由（无需 JWT）：登录、刷新令牌、令牌验证
	v1.POST("/auth/login", h.Login)
	v1.POST("/auth/refresh", h.Refresh)
	v1.POST("/authentication/super-connection-tokens/verify/", h.VerifyConnectionToken)
	// Proxy API 路由组：供内部 SSH 代理组件调用的接口，认证方式为 X-Proxy-Auth 请求头（共享密钥 + IP 白名单）
	v1.POST("/proxy/sessions", h.ProxyCreateSession)
	v1.GET("/proxy/sessions/:id", h.ProxyGetSession)
	v1.PATCH("/proxy/sessions/:id", h.ProxyUpdateSession)
	v1.GET("/proxy/ssh/host-keys", h.ProxyHostKeys)
	v1.GET("/proxy/settings/:key", h.ProxyGetSetting)
	v1.GET("/proxy/command-filter-acls", h.ProxyCommandFilterACLs)
	v1.POST("/proxy/audit-logs", h.ProxyCreateAuditLog)

	// authOnly：仅需 JWT 认证的路由组（无需 RBAC），用于登出和 MFA 操作
	authOnly := v1.Group("/auth", middleware.Auth(h.Auth))
	authOnly.GET("/access", h.Access)
	authOnly.POST("/logout", h.Logout)
	authOnly.POST("/mfa/setup", h.MFASetup)
	authOnly.POST("/mfa/verify", h.MFAVerify)

	// secure：需 JWT 认证 + Casbin RBAC 鉴权的安全路由组，覆盖用户/角色/资产/权限/会话/配置/审计管理
	secure := v1.Group("", middleware.Auth(h.Auth), middleware.RBAC(h.Enforcer))
	secure.GET("/users", h.ListUsers)
	secure.POST("/users", h.CreateUser)
	secure.GET("/users/:id", h.GetUser)
	secure.PUT("/users/:id", h.UpdateUser)
	secure.DELETE("/users/:id", h.DeleteUser)

	secure.GET("/roles", h.ListRoles)
	secure.POST("/roles", h.CreateRole)
	secure.GET("/roles/:id", h.GetRole)
	secure.PUT("/roles/:id", h.UpdateRole)
	secure.DELETE("/roles/:id", h.DeleteRole)
	secure.POST("/roles/:id/permissions", h.SetRolePermissions)
	secure.GET("/user-groups", h.ListUserGroups)

	secure.GET("/platforms", h.ListPlatforms)
	secure.POST("/platforms", h.CreatePlatform)
	secure.GET("/platforms/:id/protocols", h.ListPlatformProtocols)
	secure.GET("/assets/tree", h.AssetTree)
	secure.GET("/assets", h.ListAssets)
	secure.POST("/assets", h.CreateAsset)
	secure.GET("/assets/:id", h.GetAsset)
	secure.PUT("/assets/:id", h.UpdateAsset)
	secure.DELETE("/assets/:id", h.DeleteAsset)
	secure.GET("/assets/:id/accounts", h.ListAccounts)
	secure.POST("/assets/:id/accounts", h.CreateAccount)
	secure.GET("/assets/:id/accounts/:aid", h.GetAccount)
	secure.PUT("/assets/:id/accounts/:aid", h.UpdateAccount)
	secure.DELETE("/assets/:id/accounts/:aid", h.DeleteAccount)

	secure.GET("/permissions", h.ListPermissions)
	secure.POST("/permissions", h.CreatePermission)
	secure.GET("/permissions/:id", h.GetPermission)
	secure.PUT("/permissions/:id", h.UpdatePermission)
	secure.DELETE("/permissions/:id", h.DeletePermission)

	secure.POST("/authentication/connection-tokens/", h.IssueConnectionToken)
	// SDK URL 生成接口：为原生客户端生成带签名 Token 的连接 URL 和可下载的连接文件
	// GET：参数通过查询字符串传递（asset_id、account_id 等），适合浏览器直接使用
	// POST：参数通过 JSON 请求体传递，支持更丰富的连接配置
	secure.GET("/authentication/connection-tokens/sdk-url", h.SDKConnectionToken)
	secure.POST("/authentication/connection-tokens/sdk-url", h.SDKConnectionToken)
	secure.GET("/dashboard/summary", h.DashboardSummary)
	secure.GET("/sessions", h.ListSessions)
	secure.POST("/sessions/stream-token", h.IssueSessionStreamToken)
	v1.GET("/sessions/stream", h.StreamSessions)
	secure.POST("/sessions", h.CreateSession)
	secure.GET("/sessions/:id", h.GetSession)
	secure.GET("/sessions/:id/recording", h.SessionRecording)
	secure.POST("/sessions/:id/force-finish", h.ForceFinishSession)
	secure.GET("/sessions/:id/commands", h.ListSessionCommands)

	secure.GET("/settings", h.ListSettings)
	// SSH 主机密钥指纹（公钥摘要）查询接口，需 JWT + RBAC 认证
	secure.GET("/settings/ssh-fingerprint", h.SSHFingerprint)
	secure.GET("/settings/:key", h.GetSetting)
	secure.PUT("/settings/:key", h.UpdateSetting)
	secure.GET("/audit-logs", h.ListAuditLogs)

	mountWebUI(r, log)
	return r
}

// mountWebUI serves the built Vue SPA when a web/dist directory is available.
func mountWebUI(r *gin.Engine, log *zap.Logger) {
	distDir, ok := webDistDir()
	if !ok {
		log.Debug("web_ui_dist_not_found")
		return
	}
	indexPath := filepath.Join(distDir, "index.html")
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws/") || path == "/metrics" || strings.HasPrefix(path, "/health") {
			c.Status(http.StatusNotFound)
			return
		}
		cleaned := filepath.Clean(strings.TrimPrefix(path, "/"))
		if cleaned == "." {
			c.File(indexPath)
			return
		}
		filePath := filepath.Join(distDir, cleaned)
		if !strings.HasPrefix(filePath, distDir+string(os.PathSeparator)) && filePath != distDir {
			c.Status(http.StatusNotFound)
			return
		}
		if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
			c.File(filePath)
			return
		}
		c.File(indexPath)
	})
	log.Info("web_ui_enabled", zap.String("dir", distDir))
}

func webDistDir() (string, bool) {
	candidates := []string{}
	if configured := strings.TrimSpace(os.Getenv("TURJMP_WEB_DIST")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates, "web/dist", "/usr/share/turjmp/web")
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(filepath.Join(abs, "index.html")); err == nil && !info.IsDir() {
			return abs, true
		}
	}
	return "", false
}

// requestLogger 是 HTTP 请求日志中间件，使用 zap 记录每个请求的方法、路径、状态码和客户端 IP。
// 该中间件在请求处理完成后记录日志，不影响请求处理流程。
func requestLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		log.Info("http_request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
