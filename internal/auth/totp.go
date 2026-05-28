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

type TOTPSetup struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

func GenerateTOTP(issuer, accountName string) (TOTPSetup, error) {
	secretBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return TOTPSetup{}, err
	}
	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(secretBytes), "=")
	label := url.PathEscape(issuer + ":" + accountName)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return TOTPSetup{Secret: secret, URL: "otpauth://totp/" + label + "?" + q.Encode()}, nil
}

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
