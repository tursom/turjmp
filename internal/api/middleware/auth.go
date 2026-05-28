package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/service"
)

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

func RequireJSON(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_json", "message": err.Error()}})
		return false
	}
	return true
}
