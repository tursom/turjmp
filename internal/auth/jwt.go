// 包 auth 提供 JWT 认证（RS256 非对称签名）、密码加密（argon2id）和 TOTP 多因素认证。
//
// JWT 模块使用 RSA 2048 位密钥对进行令牌签名与验证：私钥用于签发，公钥用于校验。
// 首次启动时自动生成密钥文件并持久化到磁盘，后续启动复用已有密钥。
// access token 承载用户身份（UserID、Username、Roles），refresh token 采用 uuid.random 格式。
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tursom/turjmp/internal/config"
)

// Claims 是 JWT access token 中携带的自定义载荷，嵌入用户身份信息和标准 JWT 声明。
type Claims struct {
	UserID   int64    `json:"uid"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// JWTManager 管理 RSA 密钥对和令牌生命周期，负责 access token 的签发、解析以及 refresh token 的生成与哈希。
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewJWTManager 根据配置创建 JWTManager 实例。
// 内部调用 loadOrCreateKeyPair 加载或自动生成 RSA 密钥对，并初始化 access/refresh token 的有效期。
func NewJWTManager(cfg config.JWTConfig) (*JWTManager, error) {
	priv, pub, err := loadOrCreateKeyPair(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTManager{
		privateKey: priv,
		publicKey:  pub,
		accessTTL:  cfg.AccessTTL(),
		refreshTTL: cfg.RefreshTTL(),
	}, nil
}

// SignAccessToken 使用 RS256 算法（RSA + SHA256）签发 access token。
// 返回签名字符串、过期时间和错误。
func (m *JWTManager) SignAccessToken(userID int64, username string, roles []string) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(m.accessTTL)
	claims := Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(m.privateKey)
	return signed, expires, err
}

// ParseAccessToken 解析并验证 access token 的签名与有效性。
// 检查签名算法必须为 RS256，并使用公钥验证签名后返回 Claims。
func (m *JWTManager) ParseAccessToken(raw string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// NewRefreshToken 生成一个新的 refresh token。
// 格式为 uuid.随机字节（base64url），同时计算 SHA256 哈希用于数据库安全存储。
// 返回 token ID、原始字符串、SHA256 哈希和过期时间。
func (m *JWTManager) NewRefreshToken() (id string, raw string, hash string, expires time.Time, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", time.Time{}, err
	}
	id = uuid.NewString()
	raw = id + "." + base64.RawURLEncoding.EncodeToString(buf)
	hash = HashRefreshToken(raw)
	expires = time.Now().UTC().Add(m.refreshTTL)
	return id, raw, hash, expires, nil
}

// HashRefreshToken 计算 refresh token 原始字符串的 SHA256 哈希值（hex 编码），用于数据库安全存储。
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// loadOrCreateKeyPair 尝试从磁盘加载 RSA 密钥对，若文件不存在或加载失败则生成新的 2048 位密钥对并写入文件。
// 私钥以 PKCS#1 格式、PEM 编码存储（权限 0600），公钥以 PKIX 格式、PEM 编码存储（权限 0644）。
func loadOrCreateKeyPair(privatePath, publicPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if privatePath != "" && publicPath != "" {
		if priv, pub, err := loadKeyPair(privatePath, publicPath); err == nil {
			return priv, pub, nil
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	if err := writeKeyPair(privatePath, publicPath, priv); err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// loadKeyPair 从 PEM 文件中读取并解析 RSA 私钥（PKCS#1 格式）和公钥（PKIX 格式）。
func loadKeyPair(privatePath, publicPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privBytes, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, err
	}
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, nil, errors.New("invalid private key pem")
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		return nil, nil, errors.New("invalid public key pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("public key is not RSA")
	}
	return priv, pub, nil
}

// writeKeyPair 将 RSA 私钥（PKCS#1）和公钥（PKIX）序列化为 PEM 格式并写入磁盘。
// 私钥文件权限为 0600（仅所有者可读写），公钥文件权限为 0644。
func writeKeyPair(privatePath, publicPath string, priv *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
		return err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(privatePath, privPEM, 0o600); err != nil {
		return err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return os.WriteFile(publicPath, pubPEM, 0o644)
}
