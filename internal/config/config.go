package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	App       AppConfig       `koanf:"app"`
	HTTP      HTTPConfig      `koanf:"http"`
	Database  DatabaseConfig  `koanf:"database"`
	Security  SecurityConfig  `koanf:"security"`
	JWT       JWTConfig       `koanf:"jwt"`
	ProxyAuth ProxyAuthConfig `koanf:"proxy_auth"`
	Proxy     ProxyConfig     `koanf:"proxy"`
	TOTP      TOTPConfig      `koanf:"totp"`
	Logging   LoggingConfig   `koanf:"logging"`
	RateLimit RateLimitConfig `koanf:"rate_limit"`
}

type AppConfig struct {
	Name        string `koanf:"name"`
	Environment string `koanf:"environment"`
}

type HTTPConfig struct {
	Addr                   string `koanf:"addr"`
	ShutdownTimeoutSeconds int    `koanf:"shutdown_timeout_seconds"`
}

func (c HTTPConfig) ShutdownTimeout() time.Duration {
	if c.ShutdownTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.ShutdownTimeoutSeconds) * time.Second
}

type DatabaseConfig struct {
	Driver        string `koanf:"driver"`
	DSN           string `koanf:"dsn"`
	MigrationsDir string `koanf:"migrations_dir"`
}

type SecurityConfig struct {
	EncryptionKey     string `koanf:"encryption_key"`
	PasswordMinLength int    `koanf:"password_min_length"`
}

type JWTConfig struct {
	PrivateKeyPath    string `koanf:"private_key_path"`
	PublicKeyPath     string `koanf:"public_key_path"`
	AccessTTLSeconds  int    `koanf:"access_ttl_seconds"`
	RefreshTTLSeconds int    `koanf:"refresh_ttl_seconds"`
}

func (c JWTConfig) AccessTTL() time.Duration {
	if c.AccessTTLSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.AccessTTLSeconds) * time.Second
}

func (c JWTConfig) RefreshTTL() time.Duration {
	if c.RefreshTTLSeconds <= 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(c.RefreshTTLSeconds) * time.Second
}

type ProxyAuthConfig struct {
	Secret     string   `koanf:"secret"`
	AllowedIPs []string `koanf:"allowed_ips"`
}

// ProxyConfig 代理服务配置，包含 API 基础地址和各协议代理子配置
type ProxyConfig struct {
	// API 服务的基础 URL，供 SSH 代理等组件回调认证和 Token 验证接口
	APIBaseURL string         `koanf:"api_base_url"`
	SSH        SSHProxyConfig `koanf:"ssh"`
}

// SSHProxyConfig SSH 代理服务器配置，控制监听地址、连接数限制和超时参数
type SSHProxyConfig struct {
	// 监听地址，如 ":2222"
	Addr string `koanf:"addr"`
	// 最大并发连接数，超出后拒绝新连接，防止资源耗尽
	MaxConnections int `koanf:"max_connections"`
	// 空闲超时秒数，客户端无操作超过此时长后自动断开
	IdleTimeoutSeconds int `koanf:"idle_timeout_seconds"`
	// 连接超时秒数，连接目标主机等待的最大时长
	ConnectTimeoutSeconds int `koanf:"connect_timeout_seconds"`
}

// IdleTimeout 返回空闲超时时间，未配置时默认 15 分钟
func (c SSHProxyConfig) IdleTimeout() time.Duration {
	if c.IdleTimeoutSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.IdleTimeoutSeconds) * time.Second
}

// ConnectTimeout 返回连接超时时间，未配置时默认 15 秒
func (c SSHProxyConfig) ConnectTimeout() time.Duration {
	if c.ConnectTimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.ConnectTimeoutSeconds) * time.Second
}

// ConnectionLimit 返回最大连接数限制，未配置时默认 100
func (c SSHProxyConfig) ConnectionLimit() int {
	if c.MaxConnections <= 0 {
		return 100
	}
	return c.MaxConnections
}

type TOTPConfig struct {
	Issuer string `koanf:"issuer"`
}

type LoggingConfig struct {
	Level    string `koanf:"level"`
	Encoding string `koanf:"encoding"`
}

type RateLimitConfig struct {
	Enabled           bool    `koanf:"enabled"`
	RequestsPerSecond float64 `koanf:"requests_per_second"`
}

func Load(path string) (Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults(), "."), nil); err != nil {
		return Config{}, err
	}
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("load config %s: %w", path, err)
		}
	}
	if err := k.Load(env.Provider("TURJMP_", ".", func(s string) string {
		key := strings.TrimPrefix(s, "TURJMP_")
		return strings.ToLower(strings.ReplaceAll(key, "_", "."))
	}), nil); err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Database.Driver == "" || cfg.Database.DSN == "" {
		return Config{}, fmt.Errorf("database.driver and database.dsn are required")
	}
	if cfg.Database.MigrationsDir == "" {
		cfg.Database.MigrationsDir = "migrations/" + cfg.Database.Driver
	}
	if cfg.JWT.PrivateKeyPath == "" || cfg.JWT.PublicKeyPath == "" {
		return Config{}, fmt.Errorf("jwt private/public key paths are required")
	}
	if cfg.ProxyAuth.Secret == "" {
		return Config{}, fmt.Errorf("proxy_auth.secret is required")
	}
	return cfg, nil
}

func defaults() map[string]any {
	return map[string]any{
		"app.name":                          "Turjmp",
		"app.environment":                   "dev",
		"http.addr":                         ":8080",
		"http.shutdown_timeout_seconds":     30,
		"database.driver":                   "sqlite",
		"database.dsn":                      "file:turjmp.dev.db?_pragma=foreign_keys(ON)",
		"database.migrations_dir":           "migrations/sqlite",
		"security.encryption_key":           "dev-only-change-me-32-byte-secret",
		"security.password_min_length":      8,
		"jwt.private_key_path":              ".turjmp/jwt_private.pem",
		"jwt.public_key_path":               ".turjmp/jwt_public.pem",
		"jwt.access_ttl_seconds":            900,
		"jwt.refresh_ttl_seconds":           604800,
		"proxy_auth.secret":                 "dev-proxy-secret",
		"proxy_auth.allowed_ips":            []string{"127.0.0.1", "::1"},
		// 代理服务 API 回调地址，SSH 代理通过此地址验证 Token
		"proxy.api_base_url": "http://127.0.0.1:8080",
		// SSH 代理监听地址，默认 2222 端口
		"proxy.ssh.addr": ":2222",
		// SSH 代理最大并发连接数
		"proxy.ssh.max_connections": 100,
		// 空闲超时秒数，15 分钟无操作自动断开
		"proxy.ssh.idle_timeout_seconds": 900,
		// 连接目标主机超时秒数，15 秒未建立连接则失败
		"proxy.ssh.connect_timeout_seconds": 15,
		"totp.issuer":                       "Turjmp",
		"logging.level":                     "info",
		"logging.encoding":                  "json",
		"rate_limit.enabled":                true,
		"rate_limit.requests_per_second":    20.0,
	}
}
