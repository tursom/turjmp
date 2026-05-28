// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责权限规则的 CRUD、操作命名规范化、多对多关联表管理等业务逻辑的编排与验证。
package service

import (
	"time"

	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// PermissionService 权限管理服务，封装权限规则的 CRUD 操作，以及权限与用户、用户组、资产、节点、账户之间的多对多关联管理。
type PermissionService struct {
	store *repository.Store
}

// PermissionInput 创建或更新权限规则的输入参数，包含权限名称、允许的操作列表、有效期时间范围、激活状态，以及关联的用户、用户组、资产、节点和账户 ID 列表。
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

// NewPermissionService 创建 PermissionService 实例，注入存储层。
func NewPermissionService(store *repository.Store) *PermissionService {
	return &PermissionService{store: store}
}

// List 获取系统中所有资产权限规则的列表。
func (s *PermissionService) List() ([]domain.AssetPermission, error) {
	return s.store.ListPermissions()
}

// Get 根据 ID 获取单个权限规则及其关联的用户、组、资产、节点和账户信息（PermissionLinks）。
func (s *PermissionService) Get(id int64) (domain.AssetPermission, repository.PermissionLinks, error) {
	return s.store.GetPermission(id)
}

// Create 创建新的权限规则。流程：设置默认激活状态 → 对传入的 Actions 列表调用 NormalizeActions 进行规范化（去除空白、统一大小写等）→ 创建权限记录 → 通过 permissionLinks 辅助函数将输入中的关联 ID 转换为 PermissionLinks 结构体 → 建立多对多关联（permission_users、permission_groups、permission_assets、permission_nodes、permission_accounts 关联表）。
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

// Update 更新权限规则。流程：查找现有权限 → 覆盖 Name、Actions（已规范化）、有效期和激活状态 → 更新权限记录 → 更新所有多对多关联（先清除旧关联再重建）。
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

// Delete 删除指定权限规则及其所有关联数据。
func (s *PermissionService) Delete(id int64) error {
	return s.store.DeletePermission(id)
}

// permissionLinks 将 PermissionInput 中的关联 ID 列表转换为 PermissionLinks 结构体，作为存储层更新关联表的数据载体。
// 该方法是内部辅助函数，被 Create 和 Update 共同调用。
func permissionLinks(input PermissionInput) repository.PermissionLinks {
	return repository.PermissionLinks{
		UserIDs:    input.UserIDs,
		GroupIDs:   input.GroupIDs,
		AssetIDs:   input.AssetIDs,
		NodeIDs:    input.NodeIDs,
		AccountIDs: input.AccountIDs,
	}
}
