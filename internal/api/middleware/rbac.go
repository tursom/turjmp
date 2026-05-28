package middleware

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/api/httpx"
	"github.com/tursom/turjmp/internal/domain"
)

// RBAC 是基于 Casbin 的基于角色的访问控制中间件。从 Gin Context 中获取已认证的当前用户主体，
// 依次用用户名和角色名作为 subject 调用 Casbin Enforcer 进行权限判断。
// 请求路径（c.FullPath()）和 HTTP 方法作为 Casbin 策略匹配的 object 和 action。
// 任一 subject 匹配策略成功则放行，全部不匹配则返回 403 Forbidden。
// 该中间件必须在 Auth 中间件之后使用，依赖 Auth 中间件存入的 Principal。
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
