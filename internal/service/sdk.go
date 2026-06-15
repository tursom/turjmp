package service

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/domain"
)

// SDKURLInput 原生客户端连接信息请求的输入参数。用于描述用户请求生成原生客户端连接 URL 或下载文件所需的全部信息，包含目标资产与账户的协议、连接方式、代理主机地址以及输出格式。
// 嵌入 IssueTokenInput 以复用连接令牌签发所需的资产 ID、账户 ID、协议和连接方式等字段；ProxyHost 允许前端显式指定代理对外地址，Format 指定输出格式（如 "file" 表示下载文件）。
type SDKURLInput struct {
	IssueTokenInput        // 嵌入的令牌签发参数，包含 AssetID、AccountID、Protocol、ConnectMethod 等
	ProxyHost       string `json:"proxy_host" form:"proxy_host"` // 显式指定的代理服务对外地址（host:port），为空时自动从 API 基础地址解析
	Format          string `json:"format" form:"format"`         // 输出格式，如 "file" 表示返回文件下载内容
}

// SDKURLResult 原生客户端连接信息的完整响应载荷。包含连接令牌、服务端地址端口、生成的命令行文本、可下载文件内容以及（RDP 场景下的）WebSocket URL。
// 前端根据此结构体中的字段渲染命令行提示、生成下载文件或跳转 RDP Web 客户端。
type SDKURLResult struct {
	Token     string    `json:"token"`      // 签发的连接令牌，客户端连接时需携带此值进行认证
	ExpiresAt time.Time `json:"expires_at"` // 令牌过期时间点，超过此时间后令牌不可再使用
	ExpiresIn int       `json:"expires_in"` // 令牌剩余有效秒数，值为 0 表示已过期
	Protocol  string    `json:"protocol"`   // 小写的协议名称，如 "ssh"、"mysql"、"postgres"、"rdp"
	// ConnectMethod 连接方式标识，用于区分原生客户端连接方式：
	//   ssh: "ssh_client", mysql: "mysql_client", postgres: "postgres_client", rdp: "rdp_client" or "web_rdp"
	ConnectMethod string `json:"connect_method"`
	Host          string `json:"host"`              // 代理服务对外暴露的主机地址（不含端口），供客户端连接使用
	Port          int    `json:"port"`              // 代理服务对外暴露的端口号，对应各协议的代理监听端口
	Command       string `json:"command"`           // 可直接复制使用的命令行文本，如 "ssh -p 2222 -l user#token host"
	Filename      string `json:"filename"`          // 建议的下载文件名（含扩展名），如 "turjmp-ssh.sh"
	MimeType      string `json:"mime_type"`         // 文件内容的 MIME 类型，如 "text/x-shellscript" 或 "text/plain"
	Content       string `json:"content"`           // 文件内容，供前端直接下载或复制使用
	WebURL        string `json:"web_url,omitempty"` // RDP 协议的 WebSocket 连接 URL，仅 rdp 协议时填充
}

// BuildSDKURL 生成原生客户端连接内容（命令行、下载文件、RDP Web URL）。
// SSH/MySQL/PostgreSQL 和 Web RDP 会签发短期连接令牌；原生 RDP MITM 使用独立 RDP 代理密码认证，不签发旧连接令牌。
//
// 完整流程：
//  1. 规范化协议名称（canonicalSDKProtocol），空协议默认使用 "ssh"
//  2. 自动推断连接方式（sdkDefaultConnectMethod），如未指定则根据协议自动匹配
//  3. 解析代理监听端口（sdkProxyPort），从配置中取出对应协议的代理监听端口，若协议不支持则返回 ErrInvalidArgument
//  4. 解析代理主机地址（sdkHost），优先使用用户显式指定的 proxy_host，其次从 API 基础 URL 解析，最后回退到 127.0.0.1
//  5. 原生 RDP MITM 直接校验 connect 权限并生成 .rdp；其他协议调用 TokenService.Issue 签发连接令牌
//  6. 按协议生成命令行内容和下载文件：
//     - ssh: 生成 ssh 命令和 .sh 可执行脚本
//     - mysql: 生成 mysql 命令和纯文本内容
//     - postgres/postgresql: 生成 psql 命令（若关联数据库则附加 -d 参数）
//     - rdp: 原生 RDP 开启时生成 .rdp 文件，否则生成 WebSocket URL 和 .url 快捷方式文件
//     - 其他协议返回 ErrInvalidArgument
//
// 参数说明：
//   - userID: 发起请求的用户 ID，用于签发令牌时的权限校验
//   - input: SDK URL 生成请求参数，包含目标资产、协议、连接方式、代理主机等
//   - cfg: 代理配置，提供各协议的监听地址和 API 基础 URL
//
// 返回值：SDKURLResult 包含连接令牌、主机端口、命令行、文件内容等全部信息；error 为 nil 时调用成功
func (s *TokenService) BuildSDKURL(userID int64, input SDKURLInput, cfg config.ProxyConfig) (SDKURLResult, error) {
	// 规范化协议名称：去空格、转小写，"postgresql" 映射为 "postgres"，空字符串默认 "ssh"
	input.Protocol = canonicalSDKProtocol(input.Protocol)
	if input.Protocol == "" {
		input.Protocol = "ssh"
	}
	// 自动推断连接方式：根据协议映射到对应的客户端类型。
	if input.Protocol == "rdp" && cfg.RDP.NativeEnabled {
		input.ConnectMethod = "rdp_client"
	} else if input.ConnectMethod == "" {
		input.ConnectMethod = sdkDefaultConnectMethod(input.Protocol)
	}
	// 获取对应协议的代理监听端口，若协议不支持则端口为 0
	port := sdkProxyPort(input.Protocol, cfg)
	if port == 0 {
		return SDKURLResult{}, domain.ErrInvalidArgument
	}
	host := sdkHost(input.ProxyHost, cfg.APIBaseURL)
	if input.Protocol == "rdp" && cfg.RDP.NativeEnabled {
		return s.buildNativeRDPSDKURL(userID, input, cfg, host, port)
	}
	// 签发连接令牌，校验用户对目标资产和账户的 connect 权限
	token, err := s.Issue(userID, input.IssueTokenInput)
	if err != nil {
		return SDKURLResult{}, err
	}
	protocol := strings.ToLower(token.Protocol)
	result := SDKURLResult{
		Token:         token.Value,
		ExpiresAt:     token.ExpiresAt,
		ExpiresIn:     int(time.Until(token.ExpiresAt).Seconds()),
		Protocol:      protocol,
		ConnectMethod: token.ConnectMethod,
		Host:          host,
		Port:          port,
	}
	// 确保 ExpiresIn 不为负数（令牌已过期时置为 0）
	if result.ExpiresIn < 0 {
		result.ExpiresIn = 0
	}
	// 查询账户信息用于生成命令行中的用户名和数据库参数
	account, err := s.store.GetAccount(token.AccountID)
	if err != nil {
		return SDKURLResult{}, err
	}
	switch protocol {
	case "ssh":
		// SSH 命令格式：ssh -p <port> -l <username>#<token> <host>
		proxyUser := account.Username + "#" + token.Value
		result.Command = fmt.Sprintf("ssh -p %d -l %s %s", port, shellQuote(proxyUser), shellQuote(host))
		result.Filename = "turjmp-ssh.sh"
		result.MimeType = "text/x-shellscript"
		result.Content = "#!/bin/sh\nexec " + result.Command + "\n"
	case "mysql":
		// MySQL 命令格式：mysql -h <host> -P <port> -u <username>#<token>
		user := account.Username + "#" + token.Value
		result.Command = fmt.Sprintf("mysql -h %s -P %d -u %s", shellQuote(host), port, shellQuote(user))
		result.Filename = "turjmp-mysql.txt"
		result.MimeType = "text/plain"
		result.Content = result.Command + "\n"
	case "postgres", "postgresql":
		// PostgreSQL 命令格式：psql -h <host> -p <port> -U <username>#<token> [-d <dbname>]
		user := account.Username + "#" + token.Value
		result.Command = fmt.Sprintf("psql -h %s -p %d -U %s", shellQuote(host), port, shellQuote(user))
		if account.DBName != "" {
			result.Command += " -d " + shellQuote(account.DBName)
		}
		result.Filename = "turjmp-postgres.txt"
		result.MimeType = "text/plain"
		result.Content = result.Command + "\n"
	case "rdp":
		// RDP 原生代理未启用时保持 Web RDP 兼容输出。
		result.WebURL = sdkWebURL(cfg.RDP.ListenAddr(), host, token.Value)
		result.Command = result.WebURL
		result.Filename = "turjmp-rdp.url"
		result.MimeType = "text/plain"
		result.Content = result.WebURL + "\n"
	default:
		return SDKURLResult{}, domain.ErrInvalidArgument
	}
	return result, nil
}

func (s *TokenService) buildNativeRDPSDKURL(userID int64, input SDKURLInput, cfg config.ProxyConfig, fallbackHost string, port int) (SDKURLResult, error) {
	user, err := s.store.GetUser(userID)
	if err != nil {
		return SDKURLResult{}, err
	}
	if !user.IsActive {
		return SDKURLResult{}, domain.ErrUnauthorized
	}
	asset, err := s.store.GetAsset(input.AssetID)
	if err != nil {
		return SDKURLResult{}, err
	}
	account, err := s.store.GetAssetAccount(input.AssetID, input.AccountID)
	if err != nil {
		return SDKURLResult{}, err
	}
	if !asset.IsActive || !account.IsActive {
		return SDKURLResult{}, domain.ErrForbidden
	}
	ok, err := s.store.HasAssetPermission(userID, input.AssetID, input.AccountID, "connect")
	if err != nil {
		return SDKURLResult{}, err
	}
	if !ok {
		return SDKURLResult{}, domain.ErrForbidden
	}
	if _, err := s.store.GetAssetProtocolPort(input.AssetID, "rdp"); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return SDKURLResult{}, domain.ErrForbidden
		}
		return SDKURLResult{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(account.SecretType), "password") {
		return SDKURLResult{}, domain.ErrForbidden
	}
	host := sdkNativeRDPHost(fallbackHost, cfg)
	filename := "turjmp-rdp.rdp"
	routeUsername := fmt.Sprintf("%s#%d#%d", user.Username, input.AssetID, input.AccountID)
	return SDKURLResult{
		Protocol:      "rdp",
		ConnectMethod: "rdp_client",
		Host:          host,
		Port:          port,
		Command:       fmt.Sprintf("mstsc %s", shellQuote(filename)),
		Filename:      filename,
		MimeType:      "application/x-rdp",
		Content:       sdkRDPFileContent(host, port, routeUsername),
	}, nil
}

// sdkDefaultConnectMethod 根据协议返回对应的默认连接方式标识。
// 连接方式用于区分原生客户端类型，供前端和代理组件识别：
//   - ssh → "ssh_client"
//   - mysql → "mysql_client"
//   - postgres/postgresql → "postgres_client"
//   - rdp → "web_rdp"
//   - 其他 → "native_client"（兜底值）
func sdkDefaultConnectMethod(protocol string) string {
	switch protocol {
	case "ssh":
		return "ssh_client"
	case "mysql":
		return "mysql_client"
	case "postgres", "postgresql":
		return "postgres_client"
	case "rdp":
		return "web_rdp"
	default:
		return "native_client"
	}
}

// canonicalSDKProtocol 规范化协议名称：去除前后空格、转为小写，并将 "postgresql" 统一映射为 "postgres"。
// 空字符串同样映射为 "ssh"，作为默认协议处理。
// 返回值：规范化的协议名称字符串
func canonicalSDKProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "":
		return "ssh"
	case "postgresql":
		return "postgres"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// sdkProxyPort 根据协议从代理配置中解析对应的监听端口号。
// 各协议的端口来源：
//   - ssh → SSH 监听地址中的端口（默认 2222）
//   - mysql → MySQL 代理监听地址中的端口（默认 3307）
//   - postgres/postgresql → PostgreSQL 代理监听地址中的端口（默认 5437）
//   - rdp → RDP 代理监听地址中的端口（默认 33891）
//   - 不支持的协议 → 返回 0，调用方应据此返回错误
//
// 参数：
//   - protocol: 协议名称（"ssh"、"mysql"、"postgres"、"postgresql"、"rdp"）
//   - cfg: 代理配置，提供各协议的监听地址
//
// 返回值：解析出的端口号，协议不支持时返回 0
func sdkProxyPort(protocol string, cfg config.ProxyConfig) int {
	switch protocol {
	case "ssh":
		return listenPort(cfg.SSH.Addr, 2222)
	case "mysql":
		return listenPort(cfg.DB.MySQLListenAddr(), 3307)
	case "postgres", "postgresql":
		return listenPort(cfg.DB.PostgresListenAddr(), 5437)
	case "rdp":
		if cfg.RDP.NativeEnabled {
			return cfg.RDP.NativeClientPort()
		}
		return listenPort(cfg.RDP.ListenAddr(), 33891)
	default:
		return 0
	}
}

// sdkHost 解析代理服务对外暴露的主机地址。
//
// 解析优先级（从高到低）：
//  1. proxyHost（用户显式指定）：优先使用，支持 "host:port" 格式，自动剥离端口部分，
//     同时处理 IPv6 格式（去除方括号 "[]"）
//  2. apiBaseURL（API 基础地址）：若 proxyHost 为空，从 API 基础 URL 中提取主机名，
//     同样处理 "host:port" 和 IPv6 格式
//  3. 回退值 "127.0.0.1"：前两项均无法解析时使用本地回环地址
//
// 参数：
//   - proxyHost: 用户显式指定的代理主机地址，可为空
//   - apiBaseURL: API 服务的基础 URL，用于自动推断代理地址
//
// 返回值：解析后的主机地址（纯主机名或 IPv4/IPv6 地址，不含端口）
func sdkHost(proxyHost, apiBaseURL string) string {
	if proxyHost != "" {
		// 从 "host:port" 中剥离端口，IPv6 地址去除方括号
		host, _, err := net.SplitHostPort(proxyHost)
		if err == nil && host != "" {
			return host
		}
		return strings.Trim(proxyHost, "[]")
	}
	if u, err := url.Parse(apiBaseURL); err == nil && u.Host != "" {
		host, _, splitErr := net.SplitHostPort(u.Host)
		if splitErr == nil && host != "" {
			return host
		}
		return strings.Trim(u.Host, "[]")
	}
	// 无法解析任何有效主机时，回退到本地回环地址
	return "127.0.0.1"
}

// listenPort 从监听地址字符串中提取端口号，解析失败时返回默认值。
//
// 解析逻辑：
//  1. 若 addr 为空，直接返回 fallback
//  2. 使用 net.SplitHostPort 解析 "host:port" 格式
//  3. 若解析失败但地址以 ":" 开头（纯端口格式如 ":2222"），提取冒号后的数字
//  4. 将端口字符串转为整数，转换失败或值 ≤ 0 时返回 fallback
//
// 参数：
//   - addr: 监听地址字符串，支持 "host:port"、":port" 或纯 "port" 格式
//   - fallback: 解析失败时返回的默认端口号
//
// 返回值：解析出的端口号，或 fallback
func listenPort(addr string, fallback int) int {
	if addr == "" {
		return fallback
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 处理纯端口格式（如 ":2222"）
		if strings.HasPrefix(addr, ":") {
			port = strings.TrimPrefix(addr, ":")
		} else {
			return fallback
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// sdkWebURL 构建 RDP Web 客户端的 WebSocket 连接 URL。
// URL 格式：ws://<host>:<port>/ws/rdp/?token=<url_encoded_token>
//
// 参数：
//   - listenAddr: RDP 代理监听地址，用于提取 WebSocket 端口
//   - host: 代理对外主机地址
//   - token: 连接令牌，作为 URL 查询参数传递
//
// 返回值：可用于 RDP Web 客户端的完整 WebSocket URL
func sdkWebURL(listenAddr, host, token string) string {
	scheme := "ws"
	port := listenPort(listenAddr, 33891)
	return fmt.Sprintf("%s://%s/ws/rdp/?token=%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), url.QueryEscape(token))
}

func sdkNativeRDPHost(fallbackHost string, cfg config.ProxyConfig) string {
	if strings.TrimSpace(cfg.RDP.NativePublicHost) != "" {
		return strings.TrimSpace(cfg.RDP.NativePublicHost)
	}
	return fallbackHost
}

func sdkRDPFileContent(host string, port int, routeUsername string) string {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	lines := []string{
		"screen mode id:i:2",
		"use multimon:i:0",
		"desktopwidth:i:0",
		"desktopheight:i:0",
		"session bpp:i:32",
		"full address:s:" + address,
		"prompt for credentials:i:1",
		"authentication level:i:2",
		"enablecredsspsupport:i:1",
		"username:s:" + routeUsername,
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// shellQuote 对 Shell 参数值进行安全引用，防止命令行注入。
//
// 引用策略：
//  1. 空字符串返回两个单引号表示的空参数
//  2. 若值仅包含安全字符（字母、数字、'-'、'_'、'.'、':'、'/'、'#'），直接返回原值，无需引用
//  3. 其他情况使用单引号包裹，并转义内部单引号
//
// 参数：
//   - value: 待引用的 Shell 参数原始值
//
// 返回值：安全的、可直接拼接到命令行中的引用字符串
func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	// 检查是否所有字符都为安全字符（无需引用的情况）
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == ':' || r == '/' || r == '#' ||
			(r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'))
	}) == -1 {
		return value
	}
	// 使用单引号包裹，并将内部的单引号替换为 '\'' 转义序列
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
