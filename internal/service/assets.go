package service

import (
	"github.com/tursom/turjmp/internal/crypto"
	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type AssetService struct {
	store *repository.Store
	box   *crypto.SecretBox
}

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

func NewAssetService(store *repository.Store, box *crypto.SecretBox) *AssetService {
	return &AssetService{store: store, box: box}
}

func (s *AssetService) ListPlatforms() ([]domain.Platform, error) {
	return s.store.ListPlatforms()
}

func (s *AssetService) ListAssets() ([]domain.AssetWithPlatform, error) {
	return s.store.ListAssets()
}

func (s *AssetService) GetAsset(id int64) (domain.Asset, error) {
	return s.store.GetAsset(id)
}

func (s *AssetService) CreateAsset(a domain.Asset) (domain.Asset, error) {
	if !a.IsActive {
		a.IsActive = true
	}
	return a, s.store.CreateAsset(&a)
}

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

func (s *AssetService) DeleteAsset(id int64) error {
	return s.store.DeleteAsset(id)
}

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

func (s *AssetService) DeleteAccount(assetID, accountID int64) error {
	return s.store.DeleteAccount(assetID, accountID)
}
