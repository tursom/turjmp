package service

import (
	"strings"
	"sync"

	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type SettingService struct {
	store *repository.Store
	box   *crypto.SecretBox
	cache sync.Map
}

func NewSettingService(store *repository.Store, box *crypto.SecretBox) *SettingService {
	return &SettingService{store: store, box: box}
}

func (s *SettingService) Load() error {
	settings, err := s.store.ListSettings()
	if err != nil {
		return err
	}
	for _, setting := range settings {
		s.cache.Store(setting.Key, setting)
	}
	return nil
}

func (s *SettingService) List() (map[string][]domain.Setting, error) {
	settings, err := s.store.ListSettings()
	if err != nil {
		return nil, err
	}
	grouped := make(map[string][]domain.Setting)
	for _, setting := range settings {
		if isSecretSetting(setting) {
			setting.Value = maskSecret(setting.Value)
		}
		grouped[setting.Category] = append(grouped[setting.Category], setting)
		s.cache.Store(setting.Key, setting)
	}
	return grouped, nil
}

func (s *SettingService) Get(key string) (domain.Setting, error) {
	setting, err := s.store.GetSetting(key)
	if err != nil {
		return setting, err
	}
	if isSecretSetting(setting) {
		setting.Value = maskSecret(setting.Value)
	}
	s.cache.Store(setting.Key, setting)
	return setting, nil
}

func (s *SettingService) Update(key, value string) (domain.Setting, error) {
	setting, err := s.store.GetSetting(key)
	if err != nil {
		return setting, err
	}
	if isSecretSetting(setting) && value != "" && value != "******" {
		value, err = s.box.EncryptString(value)
		if err != nil {
			return setting, err
		}
	} else if isSecretSetting(setting) && value == "******" {
		value = setting.Value
	}
	setting.Value = value
	if err := s.store.UpsertSetting(setting); err != nil {
		return setting, err
	}
	s.cache.Store(setting.Key, setting)
	if isSecretSetting(setting) {
		setting.Value = maskSecret(setting.Value)
	}
	return setting, nil
}

func isSecretSetting(setting domain.Setting) bool {
	return setting.InputType == "secret" || strings.Contains(setting.Key, "secret") || strings.Contains(setting.Key, "access_key")
}

func maskSecret(value string) string {
	if value == "" || value == `""` {
		return value
	}
	return "******"
}
