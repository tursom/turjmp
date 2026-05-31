package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// HostKeyService 管理 SSH 主机密钥的生命周期
// 负责密钥的生成、持久化存储、查询和签名器构建，供 SSH 代理服务器使用
type HostKeyService struct {
	store *repository.Store
}

// NewHostKeyService 创建主机密钥服务实例
func NewHostKeyService(store *repository.Store) *HostKeyService {
	return &HostKeyService{store: store}
}

// EnsureDefaults 确保系统中存在默认算法（ed25519 和 RSA）的主机密钥
// 对于每种算法：若数据库中已存在则直接返回，否则生成新密钥并持久化存储
// 返回所有默认算法对应的 HostKey 列表
func (s *HostKeyService) EnsureDefaults() ([]domain.HostKey, error) {
	algorithms := []string{"ssh-ed25519", "ssh-rsa"}
	keys := make([]domain.HostKey, 0, len(algorithms))
	for _, algorithm := range algorithms {
		key, err := s.store.GetHostKeyByAlgorithm(algorithm)
		if err == nil {
			keys = append(keys, key)
			continue
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
		key, err = generateHostKey(algorithm)
		if err != nil {
			return nil, err
		}
		if err := s.store.CreateHostKey(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// List 获取所有主机密钥列表
// 内部先调用 EnsureDefaults 确保默认密钥存在，然后从数据库查询全部记录
func (s *HostKeyService) List() ([]domain.HostKey, error) {
	if _, err := s.EnsureDefaults(); err != nil {
		return nil, err
	}
	return s.store.ListHostKeys()
}

// Signers 获取所有主机密钥的 SSH 签名器（gossh.Signer）
// 将数据库中 PEM 格式的私钥解析为 crypto/ssh 签名器，供 SSH 服务端使用
// 返回的签名器列表可用于 ssh.ServerConfig 的 HostKey 配置
func (s *HostKeyService) Signers() ([]gossh.Signer, error) {
	keys, err := s.List()
	if err != nil {
		return nil, err
	}
	signers := make([]gossh.Signer, 0, len(keys))
	for _, key := range keys {
		signer, err := gossh.ParsePrivateKey([]byte(key.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("解析 %s 主机密钥失败：%w", key.Algorithm, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// generateHostKey 根据指定算法生成新的 SSH 主机密钥对
// 支持的算法：
//   - ssh-ed25519: 使用 Ed25519 曲线生成密钥并 PKCS8 编码
//   - ssh-rsa: 使用 3072 位 RSA 密钥
//
// 返回包含算法名称、SHA256 指纹、PEM 格式私钥和 OpenSSH 格式公钥的 HostKey 结构
func generateHostKey(algorithm string) (domain.HostKey, error) {
	var privateKey any
	var block *pem.Block

	switch algorithm {
	case "ssh-ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return domain.HostKey{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return domain.HostKey{}, err
		}
		privateKey = priv
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	case "ssh-rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return domain.HostKey{}, err
		}
		privateKey = priv
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	default:
		return domain.HostKey{}, domain.ErrInvalidArgument
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return domain.HostKey{}, err
	}
	publicKey := gossh.MarshalAuthorizedKey(signer.PublicKey())
	return domain.HostKey{
		Algorithm:   algorithm,
		Fingerprint: gossh.FingerprintSHA256(signer.PublicKey()),
		PrivateKey:  string(pem.EncodeToMemory(block)),
		PublicKey:   string(publicKey),
	}, nil
}
