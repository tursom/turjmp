// Package httpx 提供 Gin HTTP 框架的扩展工具集，包括当前用户主体（Principal）的存取、统一 JSON 响应格式封装和错误码映射。
// 所有 API 响应均通过本包的 JSON/Created/NoContent/Error 方法返回，确保响应格式一致。
package httpx

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
)

// principalKey 是 Gin Context 中存储当前认证用户的键名
const principalKey = "principal"

// Principal 表示当前已认证用户的身份信息，包含用户 ID、用户名及其所拥有的角色列表。
// 认证中间件在验证 JWT 后将 Principal 存入 Gin Context，后续处理链路通过 GetPrincipal/MustPrincipal 获取。
type Principal struct {
	UserID   int64    `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

// PrincipalFromClaims 从 JWT Claims 中提取用户身份信息并构造 Principal 结构体。
// 通常在认证中间件验证 Token 后调用，将 Token 中的声明转换为上下文可用的主体对象。
func PrincipalFromClaims(claims *auth.Claims) Principal {
	return Principal{UserID: claims.UserID, Username: claims.Username, Roles: claims.Roles}
}

// SetPrincipal 将用户主体信息存入 Gin Context，供后续处理链路（如 RBAC 中间件、业务 Handler）使用。
// 通常在认证中间件验证成功后被调用一次。
func SetPrincipal(c *gin.Context, principal Principal) {
	c.Set(principalKey, principal)
}

// GetPrincipal 从 Gin Context 中获取当前用户主体。ok 为 true 表示用户已认证且主体信息存在。
func GetPrincipal(c *gin.Context) (Principal, bool) {
	value, ok := c.Get(principalKey)
	if !ok {
		return Principal{}, false
	}
	principal, ok := value.(Principal)
	return principal, ok
}

// MustPrincipal 从 Gin Context 中获取当前用户主体，未认证时返回 ErrUnauthorized 错误。
// 用于需要认证的 Handler 中，无需手动判断 ok 值。
func MustPrincipal(c *gin.Context) (Principal, error) {
	principal, ok := GetPrincipal(c)
	if !ok {
		return Principal{}, domain.ErrUnauthorized
	}
	return principal, nil
}

// JSON 以统一信封格式响应 JSON 数据：{"data": data}。status 为 HTTP 状态码。
func JSON(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{"data": data})
}

// Created 以 HTTP 201 状态码返回创建成功的资源数据。
func Created(c *gin.Context, data any) {
	JSON(c, http.StatusCreated, data)
}

// NoContent 以 HTTP 204 状态码响应，表示操作成功但无返回内容（如删除操作）。
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error 将 domain 层错误映射为对应的 HTTP 状态码，并以统一格式返回错误响应：{"error": {"code": ..., "message": ...}}。
// 支持的映射：ErrInvalidArgument → 400, ErrUnauthorized → 401, ErrForbidden → 403, ErrNotFound → 404, ErrConflict → 409，其他 → 500。
func Error(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case errors.Is(err, domain.ErrInvalidArgument):
		status = http.StatusBadRequest
		code = "invalid_argument"
	case errors.Is(err, domain.ErrUnauthorized):
		status = http.StatusUnauthorized
		code = "unauthorized"
	case errors.Is(err, domain.ErrForbidden):
		status = http.StatusForbidden
		code = "forbidden"
	case errors.Is(err, domain.ErrNotFound):
		status = http.StatusNotFound
		code = "not_found"
	case errors.Is(err, domain.ErrConflict):
		status = http.StatusConflict
		code = "conflict"
	}
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": err.Error()}})
}
