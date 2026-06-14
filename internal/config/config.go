// config 包负责 Turjmp 系统的配置管理。
// 使用 koanf 库实现多层配置合并：先加载硬编码默认值，
// 再用 YAML 配置文件覆盖，最后用环境变量 TURJMP_* 覆盖。
// 环境变量使用点号分隔嵌套键，如 TURJMP_HTTP_ADDR → http.addr。
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

// Config 应用顶层配置结构体，聚合所有子配置模块。
// 通过 koanf 的 Unmarshal 从合并后的配置源填充。
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

// AppConfig 应用基础配置。
type AppConfig struct {
	Name        string `koanf:"name"`        // 应用名称，默认 "Turjmp"
	Environment string `koanf:"environment"` // 运行环境：dev（开发）、test（测试）、prod（生产）
}

// HTTPConfig HTTP 服务器配置。
type HTTPConfig struct {
	Addr                   string `koanf:"addr"`                     // 监听地址，如 ":8080"
	ShutdownTimeoutSeconds int    `koanf:"shutdown_timeout_seconds"` // 优雅关闭超时秒数
}

// ShutdownTimeout 返回优雅关闭超时时长。
// 若未配置或值 ≤ 0，则返回默认值 30 秒。
func (c HTTPConfig) ShutdownTimeout() time.Duration {
	if c.ShutdownTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.ShutdownTimeoutSeconds) * time.Second
}

// DatabaseConfig 数据库连接配置。
type DatabaseConfig struct {
	Driver        string `koanf:"driver"`         // 数据库驱动：sqlite（开发）、mysql、postgres
	DSN           string `koanf:"dsn"`            // 数据源连接字符串
	MigrationsDir string `koanf:"migrations_dir"` // 数据库迁移脚本目录路径
}

// SecurityConfig 安全相关配置。
type SecurityConfig struct {
	EncryptionKey     string `koanf:"encryption_key"`      // 密钥加密主密钥，用于 SecretBox 加解密账户凭据
	PasswordMinLength int    `koanf:"password_min_length"` // 用户密码最小长度，默认 8
}

// JWTConfig JWT 认证配置。
type JWTConfig struct {
	PrivateKeyPath    string `koanf:"private_key_path"`    // Ed25519 私钥文件路径，用于签发 Access Token
	PublicKeyPath     string `koanf:"public_key_path"`     // Ed25519 公钥文件路径，用于验证 Token 签名
	AccessTTLSeconds  int    `koanf:"access_ttl_seconds"`  // Access Token 有效期秒数
	RefreshTTLSeconds int    `koanf:"refresh_ttl_seconds"` // Refresh Token 有效期秒数
}

// AccessTTL 返回 Access Token 有效期时长。
// 若未配置或值 ≤ 0，则返回默认值 15 分钟。
func (c JWTConfig) AccessTTL() time.Duration {
	if c.AccessTTLSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.AccessTTLSeconds) * time.Second
}

// RefreshTTL 返回 Refresh Token 有效期时长。
// 若未配置或值 ≤ 0，则返回默认值 7 天。
func (c JWTConfig) RefreshTTL() time.Duration {
	if c.RefreshTTLSeconds <= 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(c.RefreshTTLSeconds) * time.Second
}

// ProxyAuthConfig SSH 代理认证配置，保护 API 与代理之间的内部通信。
type ProxyAuthConfig struct {
	Secret     string   `koanf:"secret"`      // 代理认证共享密钥，SSH 代理携带此前缀的 Token 调用 API
	AllowedIPs []string `koanf:"allowed_ips"` // 允许代理连接的 IP 白名单，如 ["127.0.0.1", "::1"]
}

// ProxyConfig 代理服务配置，包含 API 基础地址和各协议代理子配置
type ProxyConfig struct {
	// API 服务的基础 URL，供 SSH 代理等组件回调认证和 Token 验证接口
	APIBaseURL string         `koanf:"api_base_url"`
	SSH        SSHProxyConfig `koanf:"ssh"`
	DB         DBProxyConfig  `koanf:"db"`
	RDP        RDPProxyConfig `koanf:"rdp"`
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

// DBProxyConfig 数据库代理服务器配置，控制 MySQL/PG 监听地址、连接数限制和 Web DB 终端命令。
type DBProxyConfig struct {
	// MySQL 原生代理监听地址，如 ":3307"
	MySQLAddr string `koanf:"mysql_addr"`
	// PostgreSQL 原生代理监听地址。本阶段仅保留配置，不启动 PG 原生状态机。
	PostgresAddr string `koanf:"postgres_addr"`
	// 最大并发数据库代理连接数
	MaxConnections int `koanf:"max_connections"`
	// 空闲超时秒数
	IdleTimeoutSeconds int `koanf:"idle_timeout_seconds"`
	// 连接真实数据库的超时秒数
	ConnectTimeoutSeconds int `koanf:"connect_timeout_seconds"`
	// usql 可执行文件路径，用于 WebSocket DB 终端
	UsqlPath string `koanf:"usql_path"`
}

// IdleTimeout 返回数据库代理空闲超时时间，未配置时默认 30 分钟。
func (c DBProxyConfig) IdleTimeout() time.Duration {
	if c.IdleTimeoutSeconds <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(c.IdleTimeoutSeconds) * time.Second
}

// ConnectTimeout 返回连接真实数据库的超时时间，未配置时默认 15 秒。
func (c DBProxyConfig) ConnectTimeout() time.Duration {
	if c.ConnectTimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.ConnectTimeoutSeconds) * time.Second
}

// ConnectionLimit 返回最大数据库代理连接数，未配置时默认 50。
func (c DBProxyConfig) ConnectionLimit() int {
	if c.MaxConnections <= 0 {
		return 50
	}
	return c.MaxConnections
}

// MySQLListenAddr 返回 MySQL 代理监听地址。
func (c DBProxyConfig) MySQLListenAddr() string {
	if c.MySQLAddr == "" {
		return ":3307"
	}
	return c.MySQLAddr
}

// PostgresListenAddr 返回 PostgreSQL 代理监听地址。
func (c DBProxyConfig) PostgresListenAddr() string {
	if c.PostgresAddr == "" {
		return ":5437"
	}
	return c.PostgresAddr
}

// UsqlCommand 返回 usql 可执行文件路径。
func (c DBProxyConfig) UsqlCommand() string {
	if c.UsqlPath == "" {
		return "usql"
	}
	return c.UsqlPath
}

// RDPProxyConfig RDP Web 代理配置，控制 HTTP/WebSocket 监听、guacd 地址和录制暂存目录。
type RDPProxyConfig struct {
	Addr                  string `koanf:"addr"`                    // HTTP 监听地址，如 ":33891"
	GuacdAddr             string `koanf:"guacd_addr"`              // guacd sidecar TCP 地址，如 "127.0.0.1:4822"
	RecordingPath         string `koanf:"recording_path"`          // guacd 录制暂存目录
	MaxConnections        int    `koanf:"max_connections"`         // 最大并发 RDP 会话数
	IdleTimeoutSeconds    int    `koanf:"idle_timeout_seconds"`    // WebSocket/guacd 空闲超时秒数
	ConnectTimeoutSeconds int    `koanf:"connect_timeout_seconds"` // 连接 guacd 的超时秒数
	NativeEnabled         bool   `koanf:"native_enabled"`          // 是否启用原生 RDP MITM 代理
	NativeAddr            string `koanf:"native_addr"`             // 原生 RDP MITM 代理监听地址，如 ":33890"
	NativePublicHost      string `koanf:"native_public_host"`      // 生成 .rdp 文件时暴露给客户端的主机名
	NativePublicPort      int    `koanf:"native_public_port"`      // 生成 .rdp 文件时暴露给客户端的端口
	NativeCertPath        string `koanf:"native_cert_path"`        // 原生 RDP MITM 前端证书路径
	NativeKeyPath         string `koanf:"native_key_path"`         // 原生 RDP MITM 前端私钥路径
}

// ListenAddr 返回 RDP WebSocket 代理监听地址。
func (c RDPProxyConfig) ListenAddr() string {
	if c.Addr == "" {
		return ":33891"
	}
	return c.Addr
}

// GuacdListenAddr 返回 guacd TCP 地址。
func (c RDPProxyConfig) GuacdListenAddr() string {
	if c.GuacdAddr == "" {
		return "127.0.0.1:4822"
	}
	return c.GuacdAddr
}

// RecordingDir 返回 guacd 录制暂存目录。
func (c RDPProxyConfig) RecordingDir() string {
	if c.RecordingPath == "" {
		return "./recordings/rdp-tmp"
	}
	return c.RecordingPath
}

// IdleTimeout 返回 RDP 代理空闲超时时间，未配置时默认 60 分钟。
func (c RDPProxyConfig) IdleTimeout() time.Duration {
	if c.IdleTimeoutSeconds <= 0 {
		return time.Hour
	}
	return time.Duration(c.IdleTimeoutSeconds) * time.Second
}

// ConnectTimeout 返回连接 guacd 的超时时间，未配置时默认 15 秒。
func (c RDPProxyConfig) ConnectTimeout() time.Duration {
	if c.ConnectTimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.ConnectTimeoutSeconds) * time.Second
}

// ConnectionLimit 返回最大 RDP 会话数，未配置时默认 20。
func (c RDPProxyConfig) ConnectionLimit() int {
	if c.MaxConnections <= 0 {
		return 20
	}
	return c.MaxConnections
}

// NativeListenAddr 返回原生 RDP MITM 代理监听地址。
func (c RDPProxyConfig) NativeListenAddr() string {
	if c.NativeAddr == "" {
		return ":33890"
	}
	return c.NativeAddr
}

// NativeClientPort 返回 .rdp 文件中暴露给 mstsc 的端口。
func (c RDPProxyConfig) NativeClientPort() int {
	if c.NativePublicPort <= 0 {
		return 33890
	}
	return c.NativePublicPort
}

// TOTPConfig TOTP 多因子认证配置。
type TOTPConfig struct {
	Issuer string `koanf:"issuer"` // TOTP 发行者标识，显示在认证器应用中，默认 "Turjmp"
}

// LoggingConfig 日志配置。
type LoggingConfig struct {
	Level    string `koanf:"level"`    // 日志级别：debug、info、warn、error，默认 "info"
	Encoding string `koanf:"encoding"` // 日志输出格式：json（结构化）或 console（开发可读），默认 "json"
}

// RateLimitConfig API 限流配置。
type RateLimitConfig struct {
	Enabled           bool    `koanf:"enabled"`             // 是否启用限流
	RequestsPerSecond float64 `koanf:"requests_per_second"` // 每秒允许的最大请求数，默认 20
}

// Load 加载并返回完整的应用配置。
// 配置加载层级（后加载的覆盖前者）：
//  1. defaults() — 硬编码默认值
//  2. YAML 配置文件 — 通过 path 参数指定的文件路径
//  3. 环境变量 — 以 TURJMP_ 为前缀，双下划线或下划线转为点号分隔
//     例如 TURJMP_HTTP_ADDR → http.addr，TURJMP_DATABASE_DSN → database.dsn
//
// 加载完成后执行必要的校验（数据库驱动、JWT 密钥路径、代理密钥必填）。
func Load(path string) (Config, error) {
	k := koanf.New(".")
	// 第 1 层：加载硬编码默认值
	if err := k.Load(confmap.Provider(defaults(), "."), nil); err != nil {
		return Config{}, err
	}
	// 第 2 层：加载 YAML 配置文件（如提供路径）
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("load config %s: %w", path, err)
		}
	}
	// 第 3 层：加载 TURJMP_* 环境变量，自动转换分隔符
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
	// 必填项校验
	if cfg.Database.Driver == "" || cfg.Database.DSN == "" {
		return Config{}, fmt.Errorf("database.driver and database.dsn are required")
	}
	// 未配置迁移目录时按驱动自动推断
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

// defaults 返回应用配置的硬编码默认值映射。
// 作为 koanf 配置合并的第一层，确保所有字段都有默认值，
// 后续通过 YAML 文件和环境变量覆盖。
func defaults() map[string]any {
	return map[string]any{
		"app.name":                      "Turjmp",
		"app.environment":               "dev",
		"http.addr":                     ":8080",
		"http.shutdown_timeout_seconds": 30,
		"database.driver":               "sqlite",
		"database.dsn":                  "file:turjmp.dev.db?_pragma=foreign_keys(ON)",
		"database.migrations_dir":       "migrations/sqlite",
		"security.encryption_key":       "dev-only-change-me-32-byte-secret",
		"security.password_min_length":  8,
		"jwt.private_key_path":          ".turjmp/jwt_private.pem",
		"jwt.public_key_path":           ".turjmp/jwt_public.pem",
		"jwt.access_ttl_seconds":        900,
		"jwt.refresh_ttl_seconds":       604800,
		"proxy_auth.secret":             "dev-proxy-secret",
		"proxy_auth.allowed_ips":        []string{"127.0.0.1", "::1"},
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
		// 数据库代理监听地址与连接参数
		"proxy.db.mysql_addr":              ":3307",
		"proxy.db.postgres_addr":           ":5437",
		"proxy.db.max_connections":         50,
		"proxy.db.idle_timeout_seconds":    1800,
		"proxy.db.connect_timeout_seconds": 15,
		"proxy.db.usql_path":               "usql",
		// RDP Web 代理监听、guacd 连接和录制暂存配置
		"proxy.rdp.addr":                    ":33891",
		"proxy.rdp.guacd_addr":              "127.0.0.1:4822",
		"proxy.rdp.recording_path":          "./recordings/rdp-tmp",
		"proxy.rdp.max_connections":         20,
		"proxy.rdp.idle_timeout_seconds":    3600,
		"proxy.rdp.connect_timeout_seconds": 15,
		"proxy.rdp.native_enabled":          false,
		"proxy.rdp.native_addr":             ":33890",
		"proxy.rdp.native_public_host":      "",
		"proxy.rdp.native_public_port":      33890,
		"proxy.rdp.native_cert_path":        "",
		"proxy.rdp.native_key_path":         "",
		"totp.issuer":                       "Turjmp",
		"logging.level":                     "info",
		"logging.encoding":                  "json",
		"rate_limit.enabled":                true,
		"rate_limit.requests_per_second":    20.0,
	}
}
