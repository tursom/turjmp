// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件包含 SSH 客户端拨号器、认证方法构建、数据管道工具和类型定义。
package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/tursom/turjmp/internal/config"
)

// targetConfig 描述目标资产的连接信息。
// 包含目标主机的地址、端口和协议类型。
type targetConfig struct {
	Address  string // 目标主机的 IP 地址或域名
	Port     int    // 目标主机的端口号
	Protocol string // 连接协议（如 "ssh"）
}

// targetAccount 描述目标资产的账户认证信息。
// 包含登录用户名、密钥/密码、秘钥类型、提权配置和数据库名等。
type targetAccount struct {
	Username    string // 登录用户名
	Secret      string // 认证密钥（密码或 SSH 私钥内容）
	SecretType  string // 密钥类型：ssh_key（SSH 私钥）或 password（密码）
	SSHKeyType  string // SSH 密钥的类型标识
	Passphrase  string // SSH 私钥的加密密码
	SUEnabled   bool   // 是否启用超级用户提权
	SUMethod    string // 提权方式（如 su 或 sudo）
	SUAccountID *int64 // 提权目标账户的 ID
	DBName      string // 关联的数据库名称
}

// targetSessionInfo 描述会话的元数据，用于在 API 服务器上创建和跟踪会话。
type targetSessionInfo struct {
	UserID        int64  // 发起会话的用户 ID
	AssetID       int64  // 目标资产 ID
	AccountID     int64  // 使用的账户 ID
	Protocol      string // 协议类型
	Type          string // 会话类型（normal/tunnel/sftp 等）
	ConnectMethod string // 连接方式（ssh_client/web_cli 等）
	RemoteAddr    string // 用户远程地址
	RecordingPath string // 录像文件路径
	SessionID     int64  // API 服务器返回的会话 ID
	IsFinished    bool   // API 服务器记录的会话结束状态
}

// targetAuthResult 封装连接令牌验证的完整结果。
// 包含验证通过后的目标信息、账户信息和用户/资产关联信息。
type targetAuthResult struct {
	Target    targetConfig  // 目标资产连接配置
	Account   targetAccount // 目标资产账户配置
	UserID    int64         // 认证用户 ID
	AssetID   int64         // 认证资产 ID
	AccountID int64         // 认证账户 ID
}

// apiClient 定义 SSH 代理模块所需的 API 客户端接口。
// 该接口抽象了与主 API 服务器的所有通信操作，便于测试和模拟。
type apiClient interface {
	// VerifyConnectionToken 验证用户的连接令牌，返回认证后的目标信息
	VerifyConnectionToken(ctx context.Context, token, remoteAddr string) (targetAuthResult, error)
	// CreateSession 在 API 服务器上创建新的会话记录
	CreateSession(ctx context.Context, session targetSessionInfo) (targetSessionInfo, error)
	// GetSession 从 API 服务器查询会话当前状态
	GetSession(ctx context.Context, sessionID int64) (targetSessionInfo, error)
	// FinishSession 标记会话结束并保存录像路径
	FinishSession(ctx context.Context, sessionID int64, recordingPath string) error
	// ListCommandFilterACLs 获取命令过滤规则列表
	ListCommandFilterACLs(ctx context.Context) ([]commandFilterRule, error)
	// GetSetting 获取代理设置项的值
	GetSetting(ctx context.Context, key string) (string, error)
	// GetHostKeys 获取 SSH 主机密钥列表
	GetHostKeys(ctx context.Context) ([]string, error)
	// Audit 记录审计日志
	Audit(ctx context.Context, userID int64, action, resource, remoteAddr, detail string) error
}

// sshDialer 管理到目标资产的 SSH 连接池。
// 通过带缓冲的 channel 实现最大连接数限制。
type sshDialer struct {
	cfg   config.SSHProxyConfig // SSH 代理配置
	api   apiClient             // API 客户端接口
	limit chan struct{}         // 连接限制信号量（带缓冲 channel）
}

// newSSHDialer 创建一个新的 SSH 拨号器实例。
// 参数 cfg 是 SSH 代理配置，api 是 API 客户端接口。
// 返回初始化后的拨号器，连接限制数由配置决定。
func newSSHDialer(cfg config.SSHProxyConfig, api apiClient) *sshDialer {
	return &sshDialer{
		cfg:   cfg,
		api:   api,
		limit: make(chan struct{}, cfg.ConnectionLimit()),
	}
}

// acquire 尝试获取一个连接槽位。
// 通过非阻塞 channel 发送实现信号量获取。
// 返回 true 表示获取成功，false 表示连接数已满。
func (d *sshDialer) acquire() bool {
	select {
	case d.limit <- struct{}{}:
		return true
	default:
		return false
	}
}

// release 释放一个连接槽位。
// 从 channel 中取出一个元素，表示归还一个连接名额。
func (d *sshDialer) release() {
	select {
	case <-d.limit:
	default:
	}
}

// dialSSH 建立到目标资产的 SSH 连接。
// 根据账户配置构建认证方法，设置主机密钥回调（不验证）和超时时间。
// 参数 ctx 是上下文，target 是目标连接配置，account 是账户认证信息。
// 返回建立的 SSH 客户端连接，如果失败则返回错误。
func (d *sshDialer) dialSSH(ctx context.Context, target targetConfig, account targetAccount) (*gossh.Client, error) {
	auths, err := buildAuthMethods(account)
	if err != nil {
		return nil, err
	}
	clientCfg := &gossh.ClientConfig{
		User:            account.Username,
		Auth:            auths,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         d.cfg.ConnectTimeout(),
	}
	addr := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	return gossh.Dial("tcp", addr, clientCfg)
}

// buildAuthMethods 根据账户的 SecretType 构建 SSH 认证方法列表。
// 支持两种认证方式：
// - ssh_key：解析 SSH 私钥进行公钥认证
// - password 或空：使用密码认证
// 参数 account 是目标账户信息。
// 返回 SSH 认证方法切片，如果密钥类型不支持则返回错误。
func buildAuthMethods(account targetAccount) ([]gossh.AuthMethod, error) {
	switch account.SecretType {
	case "ssh_key":
		key, err := parseSSHPrivateKey(account.Secret, account.Passphrase)
		if err != nil {
			return nil, err
		}
		return []gossh.AuthMethod{gossh.PublicKeys(key)}, nil
	case "password", "":
		return []gossh.AuthMethod{gossh.Password(account.Secret)}, nil
	default:
		return nil, fmt.Errorf("不支持的凭据类型：%s", account.SecretType)
	}
}

// parseSSHPrivateKey 解析 SSH 私钥并返回签名器。
// 如果提供了密码短语（passphrase），使用加密方式解析。
// 参数 raw 是私钥的原始文本内容，passphrase 是加密密码（可为空）。
// 返回 SSH 签名器，如果解析失败则返回错误。
func parseSSHPrivateKey(raw, passphrase string) (gossh.Signer, error) {
	key := []byte(raw)
	if passphrase != "" {
		return gossh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	}
	return gossh.ParsePrivateKey(key)
}

// pipeConn 实现 net.Conn 接口，将独立的 Reader、Writer 和 Closer 组合成一个连接。
// 用于内存管道通信场景，如连接重定向或测试。
type pipeConn struct {
	io.Reader
	io.Writer
	io.Closer
	localAddr  net.Addr // 本地地址
	remoteAddr net.Addr // 远程地址
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.Writer.Write(b) }
func (p *pipeConn) Close() error                { return p.Closer.Close() }
func (p *pipeConn) LocalAddr() net.Addr         { return p.localAddr }
func (p *pipeConn) RemoteAddr() net.Addr        { return p.remoteAddr }
func (p *pipeConn) SetDeadline(time.Time) error { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error {
	return nil
}
func (p *pipeConn) SetWriteDeadline(time.Time) error {
	return nil
}

// bufferConn 实现简单的 io.ReadWriter 接口包装。
// 将独立的 Reader、Writer 和 Closer 组合，用于缓冲数据传输。
type bufferConn struct {
	io.Reader
	io.Writer
	io.Closer
}

func (b *bufferConn) Read(p []byte) (int, error)  { return b.Reader.Read(p) }
func (b *bufferConn) Write(p []byte) (int, error) { return b.Writer.Write(p) }
func (b *bufferConn) Close() error                { return b.Closer.Close() }

// copyBuffer 以 32KB 缓冲区从 src 复制数据到 dst。
// 在每次写入前调用 onWrite 回调函数，用于实现数据拦截/监控。
// 参数 dst 是目标写入器，src 是来源读取器，onWrite 是写入前的回调。
// 返回 nil 表示正常完成（遇到 EOF），否则返回错误。
func copyBuffer(dst io.Writer, src io.Reader, onWrite func([]byte) error) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if onWrite != nil {
				if err2 := onWrite(buf[:n]); err2 != nil {
					return err2
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// cloneBytes 返回字节切片的深拷贝副本。
// 避免共享底层数组，确保数据安全性。
func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}

// prefixReader 创建一个在原始读取器前添加前缀字符串的组合读取器。
// 使用 io.MultiReader 将前缀和原始数据串联为一个数据流。
// 参数 prefix 是前缀字符串，r 是原始读取器。
func prefixReader(prefix string, r io.Reader) io.Reader {
	return io.MultiReader(bytes.NewBufferString(prefix), r)
}
