package middleware

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/domain"
)

func RBAC(enforcer *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := httpx.GetPrincipal(c)
		if !ok {
			httpx.Error(c, domain.ErrUnauthorized)
			return
		}
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		method := c.Request.Method
		subjects := append([]string{principal.Username}, principal.Roles...)
		for _, subject := range subjects {
			allowed, err := enforcer.Enforce(subject, path, method)
			if err != nil {
				httpx.Error(c, err)
				return
			}
			if allowed {
				c.Next()
				return
			}
		}
		httpx.Error(c, domain.ErrForbidden)
	}
}
