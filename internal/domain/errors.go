// domain 包定义 Turjmp 系统的核心领域模型和业务错误。
// 错误变量用于在整个应用层中统一表示各类业务异常，
// 上层（handler / middleware / service）根据错误类型映射到对应的 HTTP 状态码。
package domain

import "errors"

var (
	// ErrNotFound 表示请求的资源不存在（HTTP 404）。
	// 用于数据库查询无结果、资产/用户/会话等实体未找到的场景。
	ErrNotFound = errors.New("not found")

	// ErrUnauthorized 表示请求未认证或认证凭证无效（HTTP 401）。
	// 用于 Token 过期、签名无效、用户凭据错误等场景。
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden 表示已认证用户无权访问目标资源（HTTP 403）。
	// 用于权限不足、角色不匹配、ACL 拒绝等场景。
	ErrForbidden = errors.New("forbidden")

	// ErrInvalidArgument 表示请求参数不合法（HTTP 400）。
	// 用于字段校验失败、格式错误、必填项缺失等场景。
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrConflict 表示请求与当前资源状态冲突（HTTP 409）。
	// 用于唯一约束冲突（如用户名重复）、资源已存在等场景。
	ErrConflict = errors.New("conflict")
)
