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

type Claims struct {
	UserID   int64    `json:"uid"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

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

func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

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
