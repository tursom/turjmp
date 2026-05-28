package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/api/middleware"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/repository"
)

func NewRouter(cfg config.Config, log *zap.Logger, db *repository.DB, h *handler.Handler) *gin.Engine {
	if cfg.App.Environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Metrics())
	r.Use(middleware.RateLimit(cfg.RateLimit))
	r.Use(requestLogger(log))

	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/health/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	v1 := r.Group("/api/v1")
	v1.POST("/auth/login", h.Login)
	v1.POST("/auth/refresh", h.Refresh)
	v1.POST("/authentication/super-connection-tokens/verify/", h.VerifyConnectionToken)

	authOnly := v1.Group("/auth", middleware.Auth(h.Auth))
	authOnly.POST("/logout", h.Logout)
	authOnly.POST("/mfa/setup", h.MFASetup)
	authOnly.POST("/mfa/verify", h.MFAVerify)

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

	secure.GET("/platforms", h.ListPlatforms)
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
	secure.GET("/sessions", h.ListSessions)
	secure.POST("/sessions", h.CreateSession)
	secure.GET("/sessions/:id", h.GetSession)
	secure.PATCH("/sessions/:id", h.UpdateSession)

	secure.GET("/settings", h.ListSettings)
	secure.GET("/settings/:key", h.GetSetting)
	secure.PUT("/settings/:key", h.UpdateSetting)
	secure.GET("/audit-logs", h.ListAuditLogs)
	return r
}

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
