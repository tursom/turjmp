// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
// 本文件提供 DSN（数据源名称）构建函数，用于连接到目标数据库。
// MySQL 代理使用 go-sql-driver/mysql 的 Config.FormatDSN() 格式，
// Web 终端使用 usql 支持的 URL 格式（scheme://user:password@host:port/dbname?params）。
package dbproxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// buildMySQLDSN 为 go-sql-driver/mysql 构建 DSN 连接字符串。
// 使用 mysql.Config 结构体设置用户名、密码、地址、数据库名、超时和字符集等参数，
// 然后通过 FormatDSN() 生成标准 DSN 字符串（如 user:pass@tcp(host:port)/db?timeout=10s&charset=utf8mb4）。
// 这是 MySQL 代理模式下连接目标数据库所使用的连接字符串格式。
func buildMySQLDSN(auth authResult, timeout time.Duration) string {
	cfg := mysql.NewConfig()
	cfg.User = auth.Account.Username                     // 数据库用户名
	cfg.Passwd = auth.Account.Secret                      // 数据库密码
	cfg.Net = "tcp"                                       // 使用 TCP 连接
	cfg.Addr = net.JoinHostPort(auth.Target.Address, strconv.Itoa(targetPort(auth.Target))) // 目标地址:端口
	cfg.DBName = auth.Account.DBName                      // 默认数据库
	cfg.Timeout = timeout                                 // 连接超时
	cfg.ReadTimeout = timeout                             // 读超时
	cfg.WriteTimeout = timeout                            // 写超时
	cfg.ParseTime = true                                  // 自动将 DATE/DATETIME 转为 time.Time
	cfg.Params = map[string]string{"charset": "utf8mb4"}  // 默认字符集
	return cfg.FormatDSN()
}

// buildUSQLDSN 为 usql 命令行工具构建 URL 格式的连接字符串。
// usql（通用 SQL 客户端）使用 scheme://user:password@host:port/dbname?params 格式，
// 与 go-sql-driver 的 DSN 格式不同。
// 支持 MySQL 和 PostgreSQL 两种协议：
//   - MySQL:     mysql://user:pass@host:port/dbname
//   - PostgreSQL: postgres://user:pass@host:port/dbname?sslmode=disable
func buildUSQLDSN(auth authResult) (string, error) {
	protocol := strings.ToLower(auth.Target.Protocol)
	port := targetPort(auth.Target)
	switch protocol {
	case "mysql":
		// MySQL 不需要额外参数
		return formatURLDSN("mysql", auth.Account.Username, auth.Account.Secret, auth.Target.Address, port, auth.Account.DBName, nil), nil
	case "postgres", "postgresql":
		// PostgreSQL 禁用 SSL（内网代理场景）
		query := url.Values{}
		query.Set("sslmode", "disable")
		return formatURLDSN("postgres", auth.Account.Username, auth.Account.Secret, auth.Target.Address, port, auth.Account.DBName, query), nil
	default:
		return "", fmt.Errorf("unsupported db terminal protocol %s", auth.Target.Protocol)
	}
}

// formatURLDSN 是通用的 URL 格式 DSN 构建器。
// 生成格式：scheme://username:password@host:port/dbname?query
// 若用户名不为空则设置 UserInfo 认证信息。
func formatURLDSN(scheme, username, password, host string, port int, dbName string, query url.Values) string {
	u := url.URL{
		Scheme: scheme,                                      // 协议名（mysql / postgres）
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),  // 主机:端口
		Path:   "/" + dbName,                                // 数据库名
	}
	if username != "" {
		u.User = url.UserPassword(username, password)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// normalizeDSNForTest 将 DSN 中的 URL 编码斜杠 (%2F) 还原为 /，用于测试比较。
func normalizeDSNForTest(dsn string) string {
	return strings.ReplaceAll(dsn, "%2F", "/")
}
