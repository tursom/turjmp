// crypto 包提供密钥加解密功能，用于保护数据库中的敏感凭据。
// 使用 AES-256-GCM 认证加密算法，密文以 base64 编码并加前缀 "enc:v1:"，
// 支持密钥格式自动识别（base64 原始密钥、纯文本密钥、任意长度派生出 32 字节）。
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

// encryptedPrefix 密文前缀标识，用于区分已加密和未加密的值。
// 格式为 "enc:v1:"，后续版本可升级为 "enc:v2:" 以支持密钥轮换。
const encryptedPrefix = "enc:v1:"

// SecretBox 密钥加密箱，封装 AES-GCM AEAD 实例。
// 线程安全，可并发调用 EncryptString / DecryptString。
// 用于加密数据库中的 Account.Secret、Account.Passphrase 等敏感字段。
type SecretBox struct {
	gcm cipher.AEAD // AES-GCM 认证加密实例
}

// NewSecretBox 创建密钥加密箱实例。
// 参数 key 支持以下格式（按尝试顺序）：
//   1. base64 编码的 16/24/32 字节原始密钥（优先）
//   2. 纯文本长度为 16/24/32 字节的字符串
//   3. 其他任意字符串 → SHA-256 派生为 32 字节密钥
// 返回 *SecretBox 或密钥无效时的错误。
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

// EncryptString 加密明文字符串，返回带前缀的密文。
// 加密流程：
//   1. 生成随机 nonce（12 字节）
//   2. AES-256-GCM Seal 加密 + 认证
//   3. nonce + 密文拼接，base64 RawURLEncoding 编码
//   4. 添加 "enc:v1:" 前缀
// 空字符串直接返回空字符串，不加密。
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

// DecryptString 解密密文字符串，返回原文。
// 解密流程：
//   1. 检查是否为 "enc:v1:" 前缀（无前缀则视为明文直接返回，兼容旧数据）
//   2. 去除前缀后 base64 RawURLEncoding 解码
//   3. 分离 nonce（前 12 字节）和密文
//   4. AES-256-GCM Open 解密 + 认证校验
// 空字符串直接返回空字符串。
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

// normalizeKey 将用户提供的密钥字符串规范化为 AES 所需长度的字节切片。
// 按优先级尝试：
//   1. base64 解码 → 若长度为 16/24/32 则直接使用
//   2. 原始字符串 → 若长度为 16/24/32 则直接使用
//   3. 其他情况 → SHA-256 哈希派生为 32 字节
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

// validAESKeyLen 检查长度是否为 AES 合法密钥长度（128/192/256 位）。
func validAESKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}
