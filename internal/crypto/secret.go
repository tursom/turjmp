package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encryptedPrefix = "enc:v1:"

type SecretBox struct {
	gcm cipher.AEAD
}

func NewSecretBox(key string) (*SecretBox, error) {
	normalized := normalizeKey(key)
	block, err := aes.NewCipher(normalized)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{gcm: gcm}, nil
}

func (b *SecretBox) EncryptString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := b.gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return encryptedPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (b *SecretBox) DecryptString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, encryptedPrefix) {
		return value, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, encryptedPrefix))
	if err != nil {
		return "", err
	}
	if len(raw) < b.gcm.NonceSize() {
		return "", fmt.Errorf("encrypted value too short")
	}
	nonce := raw[:b.gcm.NonceSize()]
	ciphertext := raw[b.gcm.NonceSize():]
	plain, err := b.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func normalizeKey(key string) []byte {
	if raw, err := base64.StdEncoding.DecodeString(key); err == nil {
		if validAESKeyLen(len(raw)) {
			return raw
		}
	}
	if validAESKeyLen(len(key)) {
		return []byte(key)
	}
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

func validAESKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}
