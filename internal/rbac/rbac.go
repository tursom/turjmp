package rbac

import (
	_ "embed"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"github.com/tursom/turjmp/internal/repository"
)

//go:embed model.conf
var modelText string

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
		{"operator", "/api/v1/authentication/connection-tokens/", "POST"},
		{"operator", "/api/v1/sessions", "GET|POST"},
		{"operator", "/api/v1/sessions/:id", "GET|PATCH"},
		{"auditor", "/api/v1/sessions", "GET"},
		{"auditor", "/api/v1/sessions/:id", "GET"},
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
