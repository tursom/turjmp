package httpx

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
)

const principalKey = "principal"

type Principal struct {
	UserID   int64    `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func PrincipalFromClaims(claims *auth.Claims) Principal {
	return Principal{UserID: claims.UserID, Username: claims.Username, Roles: claims.Roles}
}

func SetPrincipal(c *gin.Context, principal Principal) {
	c.Set(principalKey, principal)
}

func GetPrincipal(c *gin.Context) (Principal, bool) {
	value, ok := c.Get(principalKey)
	if !ok {
		return Principal{}, false
	}
	principal, ok := value.(Principal)
	return principal, ok
}

func MustPrincipal(c *gin.Context) (Principal, error) {
	principal, ok := GetPrincipal(c)
	if !ok {
		return Principal{}, domain.ErrUnauthorized
	}
	return principal, nil
}

func JSON(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{"data": data})
}

func Created(c *gin.Context, data any) {
	JSON(c, http.StatusCreated, data)
}

func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

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
