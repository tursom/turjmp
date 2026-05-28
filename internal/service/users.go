package service

import (
	"errors"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type UserService struct {
	store             *repository.Store
	passwordMinLength int
}

type CreateUserInput struct {
	Username string  `json:"username"`
	Name     string  `json:"name"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
	IsActive *bool   `json:"is_active"`
	RoleIDs  []int64 `json:"role_ids"`
}

type UpdateUserInput struct {
	Username string  `json:"username"`
	Name     string  `json:"name"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
	IsActive *bool   `json:"is_active"`
	RoleIDs  []int64 `json:"role_ids"`
}

func NewUserService(store *repository.Store, passwordMinLength int) *UserService {
	return &UserService{store: store, passwordMinLength: passwordMinLength}
}

func (s *UserService) List() ([]domain.User, error) {
	return s.store.ListUsers()
}

func (s *UserService) Get(id int64) (domain.User, []domain.Role, error) {
	user, err := s.store.GetUser(id)
	if err != nil {
		return user, nil, err
	}
	roles, err := s.store.UserRoles(id)
	return user, roles, err
}

func (s *UserService) Create(input CreateUserInput) (domain.User, error) {
	if len(input.Password) < s.passwordMinLength {
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
		if len(input.Password) < s.passwordMinLength {
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
	if input.RoleIDs != nil {
		if err := s.store.SetUserRoles(user.ID, input.RoleIDs); err != nil {
			return domain.User{}, err
		}
	}
	return user, nil
}

func (s *UserService) Delete(id int64) error {
	if id == 1 {
		return errors.New("cannot delete bootstrap admin")
	}
	return s.store.DeleteUser(id)
}
