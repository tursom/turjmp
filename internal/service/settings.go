// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责系统配置的读写、内存缓存、敏感值加密存储与脱敏展示等核心业务流程的编排与验证。
package service

import (
	"strings"
	"sync"

	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// SettingService 系统配置管理服务，封装配置项的读取、更新和缓存逻辑。使用 sync.Map 作为内存缓存层，减少数据库查询频率；对 secret 类型和含敏感关键字的配置项自动进行加密存储和脱敏展示。
type SettingService struct {
	store *repository.Store
	box   *crypto.SecretBox
	cache sync.Map
}

// NewSettingService 创建 SettingService 实例，注入存储层和加密模块。实例创建后需调用 Load() 方法从数据库加载配置到内存缓存。
func NewSettingService(store *repository.Store, box *crypto.SecretBox) *SettingService {
	return &SettingService{store: store, box: box}
}

// Load 从数据库加载所有配置项到内存缓存（sync.Map），通常在应用启动时调用一次，后续的 Get 和 List 操作会同步更新缓存。
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

// List 获取所有配置项，按 Category 分组后返回。安全策略：对秘密配置（inputType 为 "secret" 或 key 中含 "secret"/"access_key"）的值进行脱敏，替换为 "******"，防止敏感信息泄露。同时更新内存缓存。
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

// Get 根据 key 获取单个配置项。安全策略：若为秘密配置则对值进行脱敏后返回（"******"）。同时更新内存缓存。
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

// Update 更新指定 key 的配置值。流程：查找配置项 → 判断是否为秘密配置 → 若为秘密配置且传入的值不是空字符串也不是已脱敏值 "******"，则使用 AES-256-GCM SecretBox 加密新值后存储 → 若传入值为 "******" 则保持原值不变（表示用户未修改该字段）→ 若传入空字符串则直接存储空字符串 → 更新数据库 → 更新内存缓存 → 返回时对秘密配置进行脱敏。
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

// isSecretSetting 判断配置项是否为敏感配置。判定规则：InputType 字段为 "secret"，或 Key 中包含 "secret" 或 "access_key" 子串。
func isSecretSetting(setting domain.Setting) bool {
	return setting.InputType == "secret" || strings.Contains(setting.Key, "secret") || strings.Contains(setting.Key, "access_key")
}

// maskSecret 对敏感值进行脱敏处理。若值为空或为 JSON 空字符串 `""` 则保留原值，否则统一替换为 "******"。
func maskSecret(value string) string {
	if value == "" || value == `""` {
		return value
	}
	return "******"
}
