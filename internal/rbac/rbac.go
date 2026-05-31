// 包 rbac 基于 Casbin 实现基于角色的访问控制（RBAC）。
//
// 权限模型通过内嵌的 model.conf 文件定义，策略数据持久化在 casbin_rules 表中。
// 内置四层角色体系：super_admin（超级管理员，拥有所有权限）、admin（管理员）、
// operator（运维操作员，资产与会话管理）和 auditor（审计员，会话与审计日志只读）。
// 所有策略通过 Casbin Adapter 与数据库双向同步。
package rbac

import (
	_ "embed"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"github.com/tursom/turjmp/internal/repository"
)

//go:embed model.conf
var modelText string

// NewEnforcer 创建并初始化 Casbin Enforcer。
// 加载内嵌的模型定义和数据库适配器，从数据库读取已有策略，
// 并确保默认的 RBAC 角色策略（super_admin/admin/operator/auditor）已写入数据库。
func NewEnforcer(store *repository.Store) (*casbin.Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, err
	}
	enforcer, err := casbin.NewEnforcer(m, NewAdapter(store.DB()))
	if err != nil {
		return nil, err
	}
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, err
	}
	if err := ensureDefaultPolicies(enforcer); err != nil {
		return nil, err
	}
	return enforcer, enforcer.SavePolicy()
}

// ensureDefaultPolicies 向 Casbin Enforcer 写入系统预定义的角色权限策略。
// super_admin 和 admin 拥有对所有 API 的完全访问权限，operator 拥有资产与会话的操作权限，
// auditor 拥有会话与审计日志的只读权限。Casbin 自动去重，重复写入无副作用。
func ensureDefaultPolicies(e *casbin.Enforcer) error {
	policies := [][]string{
		{"super_admin", "/api/v1/*", ".*"},
		{"admin", "/api/v1/*", ".*"},
		{"operator", "/api/v1/assets", "GET|POST"},
		{"operator", "/api/v1/assets/:id", "GET|PUT"},
		{"operator", "/api/v1/assets/tree", "GET"},
		{"operator", "/api/v1/assets/:id/accounts", "GET|POST"},
		{"operator", "/api/v1/assets/:id/accounts/:aid", "GET|PUT"},
		{"operator", "/api/v1/platforms", "GET"},
		{"operator", "/api/v1/platforms/:id/protocols", "GET"},
		{"operator", "/api/v1/authentication/connection-tokens/", "POST"},
		// 允许 operator 角色调用 SDK URL 接口，生成可下载/可复制的原生客户端连接文件
		{"operator", "/api/v1/authentication/connection-tokens/sdk-url", "GET|POST"},
		{"operator", "/api/v1/dashboard/summary", "GET"},
		{"operator", "/api/v1/sessions", "GET|POST"},
		{"operator", "/api/v1/sessions/stream-token", "POST"},
		{"operator", "/api/v1/sessions/:id", "GET"},
		{"operator", "/api/v1/sessions/:id/recording", "GET"},
		{"operator", "/api/v1/sessions/:id/commands", "GET"},
		{"auditor", "/api/v1/dashboard/summary", "GET"},
		{"auditor", "/api/v1/sessions", "GET"},
		{"auditor", "/api/v1/sessions/stream-token", "POST"},
		{"auditor", "/api/v1/sessions/:id", "GET"},
		{"auditor", "/api/v1/sessions/:id/recording", "GET"},
		{"auditor", "/api/v1/sessions/:id/commands", "GET"},
		{"auditor", "/api/v1/audit-logs", "GET"},
	}
	for _, p := range policies {
		args := make([]any, 0, len(p))
		for _, item := range p {
			args = append(args, item)
		}
		if _, err := e.AddPolicy(args...); err != nil {
			return err
		}
	}
	return nil
}
