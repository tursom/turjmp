// 包 auth 提供 TOTP（基于时间的一次性密码）生成与验证功能，遵循 RFC 6238 标准。
//
// 算法使用 SHA1 作为 HMAC 哈希函数，生成 6 位数字验证码，时间步长为 30 秒。
// 验证时容忍 ±1 个步长窗口（即前后共 90 秒内有效），以补偿客户端与服务器之间的时钟偏差。
// QR 码 URL 使用 otpauth:// 标准格式，兼容 Google Authenticator 等主流 TOTP 客户端。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTPSetup 包含 TOTP 初始化的返回数据：Base32 编码的共享密钥和用于生成 QR 码的 otpauth:// URL。
type TOTPSetup struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// GenerateTOTP 生成 TOTP 配置信息。
// 使用加密安全随机数生成 20 字节种子，以 Base32（无填充）编码为 secret，
// 并构造 otpauth://totp/ 标准 URL（SHA1、6 位数字、30 秒周期）。
func GenerateTOTP(issuer, accountName string) (TOTPSetup, error) {
	secretBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return TOTPSetup{}, err
	}
	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(secretBytes), "=")
	return BuildTOTPSetup(issuer, accountName, secret), nil
}

// BuildTOTPSetup builds the provisioning payload for an existing TOTP secret.
func BuildTOTPSetup(issuer, accountName, secret string) TOTPSetup {
	label := url.PathEscape(issuer + ":" + accountName)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return TOTPSetup{Secret: secret, URL: "otpauth://totp/" + label + "?" + q.Encode()}
}

// ValidateTOTP 验证用户输入的 6 位 TOTP 验证码。
// 时间步长为 30 秒，容忍 ±1 个窗口（共 90 秒范围），以补偿时钟偏差。
func ValidateTOTP(code, secret string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		if generateCode(secret, now+offset) == code {
			return true
		}
	}
	return false
}

// generateCode 根据 RFC 6238 和 RFC 4226 计算指定时间步长（counter）对应的 6 位 TOTP 验证码。
// 使用 HMAC-SHA1，从 HMAC 结果中动态截断得到 31 位整数，取模 1,000,000 后零填充至 6 位。
func generateCode(secret string, counter int64) string {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	otp := binCode % 1_000_000
	return fmt.Sprintf("%06s", strconv.FormatUint(uint64(otp), 10))
}
