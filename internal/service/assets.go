// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责资产管理、凭据加密存储、资产树构建等核心业务流程的编排与验证。
package service

import (
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// AssetService 资产管理服务，封装资产和账户的 CRUD 操作、凭据加密（AES-256-GCM SecretBox）、资产树查询等业务逻辑。保管 crypto.SecretBox 用于加解密密码/密钥等敏感字段。
type AssetService struct {
	store *repository.Store
	box   *crypto.SecretBox
}

// AccountInput 创建或更新账户的输入参数，包含账户名称、用户名、凭据（密码/私钥）、凭据类型、SSH 密钥类型、凭据短语、SU 提权配置和数据库名。
type AccountInput struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	Secret      string `json:"secret"`
	SecretType  string `json:"secret_type"`
	SSHKeyType  string `json:"ssh_key_type"`
	Passphrase  string `json:"passphrase"`
	SUEnabled   bool   `json:"su_enabled"`
	SUMethod    string `json:"su_method"`
	SUAccountID *int64 `json:"su_account_id"`
	DBName      string `json:"db_name"`
	IsActive    *bool  `json:"is_active"`
}

// NewAssetService 创建 AssetService 实例，注入存储层和加密模块。
func NewAssetService(store *repository.Store, box *crypto.SecretBox) *AssetService {
	return &AssetService{store: store, box: box}
}

// ListPlatforms 获取所有协议平台（如 SSH、RDP、MySQL 等）的列表。
func (s *AssetService) ListPlatforms() ([]domain.Platform, error) {
	return s.store.ListPlatforms()
}

// ListAssets 获取所有资产及其关联平台的列表。
func (s *AssetService) ListAssets() ([]domain.AssetWithPlatform, error) {
	return s.store.ListAssets()
}

// GetAsset 根据 ID 获取单个资产的详细信息。
func (s *AssetService) GetAsset(id int64) (domain.Asset, error) {
	return s.store.GetAsset(id)
}

// CreateAsset 创建新资产。若未指定激活状态则默认设为激活（true）。
func (s *AssetService) CreateAsset(a domain.Asset) (domain.Asset, error) {
	if !a.IsActive {
		a.IsActive = true
	}
	return a, s.store.CreateAsset(&a)
}

// UpdateAsset 更新资产信息。流程：查找资产 → 覆盖 Name、Address、PlatformID、NodeID、Comment、IsActive 字段 → 更新存储。
func (s *AssetService) UpdateAsset(id int64, input domain.Asset) (domain.Asset, error) {
	asset, err := s.store.GetAsset(id)
	if err != nil {
		return domain.Asset{}, err
	}
	asset.Name = input.Name
	asset.Address = input.Address
	asset.PlatformID = input.PlatformID
	asset.NodeID = input.NodeID
	asset.Comment = input.Comment
	asset.IsActive = input.IsActive
	if err := s.store.UpdateAsset(&asset); err != nil {
		return domain.Asset{}, err
	}
	return asset, nil
}

// DeleteAsset 删除指定资产。
func (s *AssetService) DeleteAsset(id int64) error {
	return s.store.DeleteAsset(id)
}

// Tree 构建资产树结构，返回包含节点列表和资产列表的映射，供前端渲染资产拓扑树。
func (s *AssetService) Tree() (map[string]any, error) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		return nil, err
	}
	assets, err := s.store.ListAssets()
	if err != nil {
		return nil, err
	}
	return map[string]any{"nodes": nodes, "assets": assets}, nil
}

// ListAccounts 获取指定资产下的所有账户列表。安全策略：返回时将 Secret（密码/密钥）和 Passphrase（凭据短语）字段清空，防止敏感信息通过 API 泄露给前端。
func (s *AssetService) ListAccounts(assetID int64) ([]domain.Account, error) {
	accounts, err := s.store.ListAccounts(assetID)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		accounts[i].Secret = ""
		accounts[i].Passphrase = ""
	}
	return accounts, nil
}

// CreateAccount 为指定资产创建新账户。流程：使用 AES-256-GCM SecretBox 加密明文 Secret（密码/私钥）和 Passphrase（凭据短语）→ 若未指定凭据类型则默认设为 "password" → 若未指定激活状态则默认激活 → 创建账户记录 → 返回时清空 Secret 和 Passphrase 字段以保护敏感信息不通过 API 暴露。
func (s *AssetService) CreateAccount(assetID int64, input AccountInput) (domain.Account, error) {
	secret, err := s.box.EncryptString(input.Secret)
	if err != nil {
		return domain.Account{}, err
	}
	passphrase, err := s.box.EncryptString(input.Passphrase)
	if err != nil {
		return domain.Account{}, err
	}
	active := true
	if input.IsActive != nil {
		active = *input.IsActive
	}
	secretType := input.SecretType
	if secretType == "" {
		secretType = "password"
	}
	account := domain.Account{
		AssetID:     assetID,
		Name:        input.Name,
		Username:    input.Username,
		Secret:      secret,
		SecretType:  secretType,
		SSHKeyType:  input.SSHKeyType,
		Passphrase:  passphrase,
		SUEnabled:   input.SUEnabled,
		SUMethod:    input.SUMethod,
		SUAccountID: input.SUAccountID,
		DBName:      input.DBName,
		IsActive:    active,
	}
	if err := s.store.CreateAccount(&account); err != nil {
		return domain.Account{}, err
	}
	account.Secret = ""
	account.Passphrase = ""
	return account, nil
}

// UpdateAccount 更新指定资产下的账户信息。流程：查找现有账户 → 覆盖非敏感字段 → 若传入了新的 Secret 则使用 SecretBox 加密后更新 → 若传入了新的 Passphrase 则加密后更新 → 更新存储 → 返回时清空 Secret 和 Passphrase 字段以保护敏感信息不通过 API 暴露。
// Secret 和 Passphrase 为空字符串时表示不修改原有值。
func (s *AssetService) UpdateAccount(assetID, accountID int64, input AccountInput) (domain.Account, error) {
	account, err := s.store.GetAssetAccount(assetID, accountID)
	if err != nil {
		return domain.Account{}, err
	}
	account.Name = input.Name
	account.Username = input.Username
	account.SecretType = input.SecretType
	if account.SecretType == "" {
		account.SecretType = "password"
	}
	account.SSHKeyType = input.SSHKeyType
	account.SUEnabled = input.SUEnabled
	account.SUMethod = input.SUMethod
	account.SUAccountID = input.SUAccountID
	account.DBName = input.DBName
	if input.IsActive != nil {
		account.IsActive = *input.IsActive
	}
	if input.Secret != "" {
		account.Secret, err = s.box.EncryptString(input.Secret)
		if err != nil {
			return domain.Account{}, err
		}
	}
	if input.Passphrase != "" {
		account.Passphrase, err = s.box.EncryptString(input.Passphrase)
		if err != nil {
			return domain.Account{}, err
		}
	}
	if err := s.store.UpdateAccount(&account); err != nil {
		return domain.Account{}, err
	}
	account.Secret = ""
	account.Passphrase = ""
	return account, nil
}

// DeleteAccount 删除指定资产下的指定账户。
func (s *AssetService) DeleteAccount(assetID, accountID int64) error {
	return s.store.DeleteAccount(assetID, accountID)
}
