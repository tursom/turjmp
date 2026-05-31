// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责用户管理、角色绑定、密码安全策略等核心业务流程的编排与验证。
package service

import (
	"errors"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// UserService 用户管理服务，封装用户的 CRUD 操作、密码哈希策略（argon2id）、角色分配等业务逻辑。通过 passwordMinLength 控制密码最小长度策略。
type UserService struct {
	store             *repository.Store
	passwordMinLength int
}

// CreateUserInput 创建用户的输入参数，包含用户名、显示名、邮箱、明文密码、激活状态和角色 ID 列表。
type CreateUserInput struct {
	Username string  `json:"username"`
	Name     string  `json:"name"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
	IsActive *bool   `json:"is_active"`
	RoleIDs  []int64 `json:"role_ids"`
}

// UpdateUserInput 更新用户的输入参数，与 CreateUserInput 结构相同，不为空的字段将覆盖原有值。
type UpdateUserInput struct {
	Username string  `json:"username"`
	Name     string  `json:"name"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
	IsActive *bool   `json:"is_active"`
	RoleIDs  []int64 `json:"role_ids"`
}

// NewUserService 创建 UserService 实例，注入存储层并设置密码最小长度策略。
func NewUserService(store *repository.Store, passwordMinLength int) *UserService {
	return &UserService{store: store, passwordMinLength: passwordMinLength}
}

// List 获取系统中所有用户的列表。
func (s *UserService) List() ([]domain.User, error) {
	return s.store.ListUsers()
}

// Get 根据 ID 获取单个用户及其关联的角色列表。
func (s *UserService) Get(id int64) (domain.User, []domain.Role, error) {
	user, err := s.store.GetUser(id)
	if err != nil {
		return user, nil, err
	}
	roles, err := s.store.UserRoles(id)
	return user, roles, err
}

// Create 创建新用户。流程：校验密码长度 → 使用 argon2id 哈希明文密码 → 设置默认激活状态 → 创建用户记录 → 若传入了角色 ID 列表则绑定角色。
// 密码长度不足时返回 domain.ErrInvalidArgument。
func (s *UserService) Create(input CreateUserInput) (domain.User, error) {
	if len(input.Password) < s.effectivePasswordMinLength() {
		return domain.User{}, domain.ErrInvalidArgument
	}
	hash, err := auth.HashPassword(input.Password)
	if err != nil {
		return domain.User{}, err
	}
	active := true
	if input.IsActive != nil {
		active = *input.IsActive
	}
	user := domain.User{
		Username:     input.Username,
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: hash,
		IsActive:     active,
	}
	if err := s.store.CreateUser(&user); err != nil {
		return domain.User{}, err
	}
	if input.RoleIDs != nil {
		if err := s.store.SetUserRoles(user.ID, input.RoleIDs); err != nil {
			return domain.User{}, err
		}
	}
	return user, nil
}

// Update 更新用户信息。流程：查找用户 → 非空字段覆盖（Username、Name、Email、IsActive）→ 若传入新密码则校验长度并使用 argon2id 重新哈希 → 更新用户记录 → 若传入角色 ID 列表则重新设置角色绑定。
// 密码字段为空字符串时表示不修改密码。
func (s *UserService) Update(id int64, input UpdateUserInput) (domain.User, error) {
	user, err := s.store.GetUser(id)
	if err != nil {
		return domain.User{}, err
	}
	if input.Username != "" {
		user.Username = input.Username
	}
	user.Name = input.Name
	user.Email = input.Email
	if input.IsActive != nil {
		user.IsActive = *input.IsActive
	}
	if input.Password != "" {
		if len(input.Password) < s.effectivePasswordMinLength() {
			return domain.User{}, domain.ErrInvalidArgument
		}
		hash, err := auth.HashPassword(input.Password)
		if err != nil {
			return domain.User{}, err
		}
		user.PasswordHash = hash
	}
	if err := s.store.UpdateUser(&user); err != nil {
		return domain.User{}, err
	}
	if input.IsActive != nil && !*input.IsActive {
		if err := s.store.RevokeUserRefreshTokens(user.ID); err != nil {
			return domain.User{}, err
		}
	}
	if input.RoleIDs != nil {
		if err := s.store.SetUserRoles(user.ID, input.RoleIDs); err != nil {
			return domain.User{}, err
		}
	}
	return user, nil
}

func (s *UserService) effectivePasswordMinLength() int {
	minLength := settingInt(s.store, "security.password_min_length", s.passwordMinLength)
	if minLength <= 0 {
		return s.passwordMinLength
	}
	return minLength
}

// Delete 删除指定用户。内置保护措施：禁止删除 ID 为 1 的用户（系统引导管理员），确保总有一个超级管理员账户存在。
func (s *UserService) Delete(id int64) error {
	if id == 1 {
		return errors.New("cannot delete bootstrap admin")
	}
	return s.store.DeleteUser(id)
}
