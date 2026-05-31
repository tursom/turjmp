// 包 auth 提供密码哈希与验证功能，基于 argon2id 算法实现安全的密码存储与校验。
//
// 哈希存储格式：$argon2id$v=19$m=<内存>$t=<迭代>$p=<并行度>$<base64盐>$<base64哈希>
// 验证时从已存储的哈希字符串中解析参数并重新计算，使用 subtle.ConstantTimeCompare 进行常量时间比较以防御时序攻击。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// argon2id 参数：64 MB 内存、3 轮迭代、2 路并行、16 字节盐、32 字节输出密钥。
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16
	argonKeyLength   = 32
)

// HashPassword 使用 argon2id 算法对明文密码进行哈希。
// 返回格式化的哈希字符串：$argon2id$v=19$m=65536,t=3,p=2$<base64盐>$<base64哈希>。
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword 验证明文密码与已存储的 argon2id 哈希是否匹配。
// 从哈希字符串中解析参数（内存、迭代、并行度、盐值），重新计算并做常量时间比较以防御时序攻击。
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("无效的密码哈希格式")
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, fmt.Errorf("无效的 argon2 参数")
	}
	memory, err := parseParam(params[0], "m")
	if err != nil {
		return false, err
	}
	iterations, err := parseParam(params[1], "t")
	if err != nil {
		return false, err
	}
	parallelism, err := parseParam(params[2], "p")
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

// parseParam 解析 argon2 参数串中的 key=value 对（如 m=65536），返回整数值。
func parseParam(part, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(part, prefix) {
		return 0, fmt.Errorf("缺少 argon2 参数：%s", key)
	}
	return strconv.Atoi(strings.TrimPrefix(part, prefix))
}
