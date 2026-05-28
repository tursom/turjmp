package service

import (
	"time"

	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type PermissionService struct {
	store *repository.Store
}

type PermissionInput struct {
	Name        string     `json:"name"`
	Actions     []string   `json:"actions"`
	DateStart   *time.Time `json:"date_start"`
	DateExpired *time.Time `json:"date_expired"`
	IsActive    *bool      `json:"is_active"`
	UserIDs     []int64    `json:"user_ids"`
	GroupIDs    []int64    `json:"group_ids"`
	AssetIDs    []int64    `json:"asset_ids"`
	NodeIDs     []int64    `json:"node_ids"`
	AccountIDs  []int64    `json:"account_ids"`
}

func NewPermissionService(store *repository.Store) *PermissionService {
	return &PermissionService{store: store}
}

func (s *PermissionService) List() ([]domain.AssetPermission, error) {
	return s.store.ListPermissions()
}

func (s *PermissionService) Get(id int64) (domain.AssetPermission, repository.PermissionLinks, error) {
	return s.store.GetPermission(id)
}

func (s *PermissionService) Create(input PermissionInput) (domain.AssetPermission, error) {
	active := true
	if input.IsActive != nil {
		active = *input.IsActive
	}
	p := domain.AssetPermission{
		Name:        input.Name,
		Actions:     repository.NormalizeActions(input.Actions),
		DateStart:   input.DateStart,
		DateExpired: input.DateExpired,
		IsActive:    active,
	}
	return p, s.store.CreatePermission(&p, permissionLinks(input))
}

func (s *PermissionService) Update(id int64, input PermissionInput) (domain.AssetPermission, error) {
	p, _, err := s.store.GetPermission(id)
	if err != nil {
		return domain.AssetPermission{}, err
	}
	p.Name = input.Name
	p.Actions = repository.NormalizeActions(input.Actions)
	p.DateStart = input.DateStart
	p.DateExpired = input.DateExpired
	if input.IsActive != nil {
		p.IsActive = *input.IsActive
	}
	return p, s.store.UpdatePermission(&p, permissionLinks(input))
}

func (s *PermissionService) Delete(id int64) error {
	return s.store.DeletePermission(id)
}

func permissionLinks(input PermissionInput) repository.PermissionLinks {
	return repository.PermissionLinks{
		UserIDs:    input.UserIDs,
		GroupIDs:   input.GroupIDs,
		AssetIDs:   input.AssetIDs,
		NodeIDs:    input.NodeIDs,
		AccountIDs: input.AccountIDs,
	}
}
