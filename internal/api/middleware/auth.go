// Package middleware 提供 Gin 框架的 HTTP 中间件，包括 JWT 认证、Casbin RBAC 鉴权、Prometheus 指标采集和令牌桶限流。
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/service"
)

// Auth 是 JWT Bearer Token 认证中间件。从 Authorization 请求头提取 Bearer Token，
// 调用 AuthService 解析并验证 Token 有效性，验证通过后将用户主体信息（Principal）存入 Gin Context。
// 验证失败时返回 401 Unauthorized。authService 为认证服务实例，负责 Token 的解析和校验。
func Auth(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			httpx.Error(c, domain.ErrUnauthorized)
			return
		}
		claims, err := authService.ParseAccessToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		if err != nil {
			httpx.Error(c, domain.ErrUnauthorized)
			return
		}
		httpx.SetPrincipal(c, httpx.PrincipalFromClaims(claims))
		c.Next()
	}
}

// RequireJSON 绑定请求体 JSON 到目标结构体 dst，绑定失败时返回 400 Bad Request 错误响应。
// 返回值表示绑定是否成功，调用方应在失败时直接 return 避免继续执行后续逻辑。
func RequireJSON(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_json", "message": err.Error()}})
		return false
	}
	return true
}
