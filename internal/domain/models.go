// domain 包定义 Turjmp 系统的核心领域模型。
// 模型与数据库表结构一一对应，使用 sqlx db tag 映射数据库字段，
// 使用 json tag 控制 JSON 序列化行为（"-" 表示序列化时隐藏敏感字段）。
package domain

import "time"

// User 系统用户模型，存储用户身份、认证和 MFA 信息。
// 与 user_groups / asset_permissions 等表通过关联表建立多对多关系。
type User struct {
	ID           int64      `db:"id" json:"id"`
	Username     string     `db:"username" json:"username"`                     // 登录用户名，唯一标识
	Name         string     `db:"name" json:"name"`                             // 用户显示名称
	Email        string     `db:"email" json:"email"`                           // 邮箱地址
	PasswordHash string     `db:"password_hash" json:"-"`                       // bcrypt 密码哈希，JSON 序列化时隐藏
	MFAEnabled   bool       `db:"mfa_enabled" json:"mfa_enabled"`               // 是否启用多因子认证（TOTP）
	MFASecret    string     `db:"mfa_secret" json:"-"`                          // TOTP 共享密钥，JSON 序列化时隐藏
	IsActive     bool       `db:"is_active" json:"is_active"`                   // 账户是否激活，禁用后无法登录
	LastLoginAt  *time.Time `db:"last_login_at" json:"last_login_at,omitempty"` // 最近一次登录时间，可为空
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`                 // 账户创建时间
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`                 // 最近更新时间
}

// RDPProxyCredential 保存用户用于原生 RDP MITM 代理前端认证的独立密码哈希。
// 它与 users.password_hash 相互独立，避免复用 Web 登录密码。
type RDPProxyCredential struct {
	UserID       int64      `db:"user_id" json:"user_id"`
	PasswordHash string     `db:"password_hash" json:"-"`
	IsEnabled    bool       `db:"is_enabled" json:"is_enabled"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
	DisabledAt   *time.Time `db:"disabled_at" json:"disabled_at"`
}

// Role 角色模型，用于 RBAC 权限控制。
// 用户通过关联表绑定角色，角色决定用户能访问哪些资源和执行哪些操作。
type Role struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`               // 角色名称，如 admin、operator、auditor
	Description string    `db:"description" json:"description"` // 角色描述说明
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// UserGroup 用户组模型，用于批量管理用户权限。
// 用户可通过关联表加入多个用户组，组级权限统一应用到组内所有成员。
// OrgID 关联到组织节点，实现多租户隔离。
type UserGroup struct {
	ID        int64     `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`     // 用户组名称
	OrgID     int64     `db:"org_id" json:"org_id"` // 所属组织 ID，关联 Node 表中 org 类型节点
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// Platform 资产平台模型，定义资产的连接类型（如 Linux、Windows、MySQL 等）。
// 每个 Asset 通过 PlatformID 关联到一个平台。
type Platform struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`               // 平台名称，如 Linux Server、MySQL Database
	Type        string    `db:"type" json:"type"`               // 平台类型标识，如 linux、windows、mysql
	Description string    `db:"description" json:"description"` // 平台描述
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// PlatformProtocol 平台协议模型，定义每个平台支持的连接协议和端口。
// 例如 Linux 平台可能支持 SSH（端口 22）和 Telnet（端口 23）。
// PlatformID 关联到 Platform 表。
type PlatformProtocol struct {
	ID         int64     `db:"id" json:"id"`
	PlatformID int64     `db:"platform_id" json:"platform_id"` // 所属平台 ID
	Name       string    `db:"name" json:"name"`               // 协议名称，如 ssh、rdp、mysql
	Port       int       `db:"port" json:"port"`               // 协议默认端口号
	Settings   string    `db:"settings" json:"settings"`       // 协议配置项（JSON 字符串），如字符集等
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

// Node 组织节点模型，用于构建树形组织结构。
// 支持无限层级嵌套：ParentID 指向父节点，为 nil 表示根节点。
// OrgID 用于多租户数据隔离，同一组织下的节点归该组织所有。
type Node struct {
	ID        int64     `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`                     // 节点名称
	ParentID  *int64    `db:"parent_id" json:"parent_id,omitempty"` // 父节点 ID，nil 表示根节点
	OrgID     int64     `db:"org_id" json:"org_id"`                 // 所属组织 ID
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// Asset 资产模型，表示一台可被连接的远程主机或数据库实例。
// PlatformID 关联 Platform 表，决定使用何种协议连接。
// NodeID 关联 Node 表，将资产归入某个组织节点，nil 表示未分配节点。
type Asset struct {
	ID         int64     `db:"id" json:"id"`
	Name       string    `db:"name" json:"name"`                 // 资产名称
	Address    string    `db:"address" json:"address"`           // 连接地址（IP 或域名）
	PlatformID int64     `db:"platform_id" json:"platform_id"`   // 关联的平台 ID → Platform
	NodeID     *int64    `db:"node_id" json:"node_id,omitempty"` // 所属组织节点 ID → Node，nil 表示未归类
	Comment    string    `db:"comment" json:"comment"`           // 备注信息
	IsActive   bool      `db:"is_active" json:"is_active"`       // 资产是否启用
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// AssetWithPlatform 资产与平台信息联合查询结果。
// 嵌入 Asset 并追加平台名称和类型字段，用于列表展示时避免 N+1 查询。
type AssetWithPlatform struct {
	Asset               // 嵌入 Asset 所有字段
	PlatformName string `db:"platform_name" json:"platform_name"` // 平台名称（来自 platforms 表 JOIN）
	PlatformType string `db:"platform_type" json:"platform_type"` // 平台类型（来自 platforms 表 JOIN）
}

// Account 资产账户模型，存储连接到某个资产所需的认证凭据。
// AssetID 关联 Asset 表，一个资产可以有多个账户（如 root 账户、普通账户）。
// Secret 字段存储加密后的密码或 SSH 私钥，JSON 序列化时隐藏。
type Account struct {
	ID          int64     `db:"id" json:"id"`
	AssetID     int64     `db:"asset_id" json:"asset_id"`                     // 关联的资产 ID → Asset
	Name        string    `db:"name" json:"name"`                             // 账户显示名称
	Username    string    `db:"username" json:"username"`                     // 登录用户名
	Secret      string    `db:"secret" json:"-"`                              // 加密后的密码/密钥，JSON 序列化时隐藏
	SecretType  string    `db:"secret_type" json:"secret_type"`               // 凭据类型：password（密码）、ssh_key（SSH 密钥）
	SSHKeyType  string    `db:"ssh_key_type" json:"ssh_key_type"`             // SSH 密钥算法，如 ssh-rsa、ecdsa-sha2-nistp256
	Passphrase  string    `db:"passphrase" json:"-"`                          // SSH 密钥口令，JSON 序列化时隐藏
	SUEnabled   bool      `db:"su_enabled" json:"su_enabled"`                 // 是否启用特权提升（su/sudo）
	SUMethod    string    `db:"su_method" json:"su_method"`                   // 特权提升方式：su 或 sudo
	SUAccountID *int64    `db:"su_account_id" json:"su_account_id,omitempty"` // 提升到的目标账户 ID，nil 表示不切换
	DBName      string    `db:"db_name" json:"db_name"`                       // 数据库名称（仅数据库类资产使用）
	IsActive    bool      `db:"is_active" json:"is_active"`                   // 账户是否启用
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// AssetPermission 资产权限模型，定义用户对资产的访问权限规则。
// 通过关联表绑定用户/用户组和资产，控制连接、上传、下载等操作。
// DateStart 和 DateExpired 支持临时授权的时间窗口。
type AssetPermission struct {
	ID          int64      `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`                           // 权限规则名称
	Actions     string     `db:"actions" json:"actions"`                     // 允许的操作列表（JSON 数组），如 ["connect","upload","download"]
	DateStart   *time.Time `db:"date_start" json:"date_start,omitempty"`     // 授权起始时间，nil 表示立即生效
	DateExpired *time.Time `db:"date_expired" json:"date_expired,omitempty"` // 授权过期时间，nil 表示永不过期
	IsActive    bool       `db:"is_active" json:"is_active"`                 // 权限是否启用
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`
}

// ConnectionToken 连接凭据模型，用于生成一次性或可复用的连接 Token。
// 用户获得授权后生成 Token，凭此 Token 通过 SSH 代理连接到目标资产。
// IsReusable 控制 Token 是单次使用还是可多次使用。
type ConnectionToken struct {
	ID             int64      `db:"id" json:"id"`
	Value          string     `db:"value" json:"value"`                     // Token 值（UUID 字符串）
	UserID         int64      `db:"user_id" json:"user_id"`                 // 关联的用户 ID → User
	AssetID        int64      `db:"asset_id" json:"asset_id"`               // 关联的资产 ID → Asset
	AccountID      int64      `db:"account_id" json:"account_id"`           // 关联的账号 ID → Account
	Protocol       string     `db:"protocol" json:"protocol"`               // 连接协议，如 ssh、rdp
	ConnectMethod  string     `db:"connect_method" json:"connect_method"`   // 连接方式：direct（直连）或 proxy（代理转发）
	IsReusable     bool       `db:"is_reusable" json:"is_reusable"`         // 是否可重复使用，false 则使用后立即失效
	ConnectOptions string     `db:"connect_options" json:"connect_options"` // 连接选项（JSON 字符串），如终端大小、编码等
	UsedAt         *time.Time `db:"used_at" json:"used_at,omitempty"`       // 首次使用时间，nil 表示未使用
	ExpiresAt      time.Time  `db:"expires_at" json:"expires_at"`           // Token 过期时间
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}

// Session 会话模型，记录每次用户连接资产的会话信息。
// 包含连接来源、远程地址、会话录制路径等审计所需数据。
// Type 字段区分 Web 终端会话和直接 SSH 代理会话。
type Session struct {
	ID            int64      `db:"id" json:"id"`
	UserID        int64      `db:"user_id" json:"user_id"`               // 发起会话的用户 ID → User
	AssetID       int64      `db:"asset_id" json:"asset_id"`             // 连接的资产 ID → Asset
	AccountID     int64      `db:"account_id" json:"account_id"`         // 使用的账户 ID → Account
	Protocol      string     `db:"protocol" json:"protocol"`             // 会话使用的协议
	Type          string     `db:"type" json:"type"`                     // 会话类型：web（Web 终端）或 ssh（SSH 代理）
	LoginFrom     string     `db:"login_from" json:"login_from"`         // 登录来源，如 web、ssh_client
	RemoteAddr    string     `db:"remote_addr" json:"remote_addr"`       // 客户端 IP 地址
	RecordingPath string     `db:"recording_path" json:"recording_path"` // 会话录制文件路径（asciicast / ttyrec 格式）
	IsFinished    bool       `db:"is_finished" json:"is_finished"`       // 会话是否已结束
	DateStart     time.Time  `db:"date_start" json:"date_start"`         // 会话开始时间
	DateEnd       *time.Time `db:"date_end" json:"date_end,omitempty"`   // 会话结束时间，nil 表示仍在进行中
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
}

// SessionSummary 是仪表盘/列表场景使用的会话摘要，追加用户、资产和账号展示名。
type SessionSummary struct {
	Session
	Username    string `db:"username" json:"username"`
	UserName    string `db:"user_name" json:"user_name"`
	AssetName   string `db:"asset_name" json:"asset_name"`
	AccountName string `db:"account_name" json:"account_name"`
}

// Setting 系统设置模型，以键值对形式存储全局配置项。
// 通过 Category 分组，支持多种 InputType（文本、开关、下拉等），
// Options 字段用于下拉/单选等需要预定义选项的控件。
type Setting struct {
	Key         string    `db:"key" json:"key"`                 // 设置项键名，主键
	Value       string    `db:"value" json:"value"`             // 设置项值
	Category    string    `db:"category" json:"category"`       // 设置分类，如 security、display、connection
	Label       string    `db:"label" json:"label"`             // 界面显示的标签文字
	Description string    `db:"description" json:"description"` // 设置项描述说明
	InputType   string    `db:"input_type" json:"input_type"`   // 界面控件类型：text、number、switch、select 等
	Options     string    `db:"options" json:"options"`         // 可选值列表（JSON 数组），用于 select/radio 控件
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// RefreshToken 刷新 Token 模型，用于 JWT 双 Token 机制。
// 用户登录后获取短期的 Access Token 和长期的 Refresh Token，
// TokenHash 存储 Refresh Token 的 SHA-256 哈希值，原始 Token 仅返回一次。
type RefreshToken struct {
	ID        string     `db:"id" json:"id"`                           // Token 唯一标识（UUID）
	UserID    int64      `db:"user_id" json:"user_id"`                 // 关联的用户 ID → User
	TokenHash string     `db:"token_hash" json:"-"`                    // Refresh Token 的哈希值，JSON 序列化时隐藏
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`           // 过期时间
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"` // 撤销时间，nil 表示未撤销
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

// AuditLog 审计日志模型，记录系统中的关键操作事件。
// 用于安全审计和操作追溯，记录操作人、操作类型、目标资源和详细信息。
// UserID 可为 nil（如系统自动操作、未认证请求等场景）。
type AuditLog struct {
	ID         int64     `db:"id" json:"id"`
	UserID     *int64    `db:"user_id" json:"user_id,omitempty"` // 操作人用户 ID，nil 表示系统或未认证操作
	Action     string    `db:"action" json:"action"`             // 操作类型：login、logout、create、update、delete、connect 等
	Resource   string    `db:"resource" json:"resource"`         // 操作目标资源类型，如 user、asset、session
	RemoteAddr string    `db:"remote_addr" json:"remote_addr"`   // 客户端 IP 地址
	Detail     string    `db:"detail" json:"detail"`             // 操作详情（JSON 字符串），包含变更前后的数据对比
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

// HostKey SSH 主机密钥模型，存储代理服务器生成的密钥对，用于 SSH 连接时验证身份
type HostKey struct {
	ID int64 `db:"id" json:"id"`
	// 密钥算法类型，如 ssh-rsa、ecdsa-sha2-nistp256
	Algorithm string `db:"algorithm" json:"algorithm"`
	// 密钥指纹，用于展示和验证密钥唯一性
	Fingerprint string `db:"fingerprint" json:"fingerprint"`
	// 私钥内容（PEM 格式），JSON 序列化时隐藏
	PrivateKey string `db:"private_key" json:"-"`
	// 公钥内容（OpenSSH 格式），用于远程主机 authorized_keys
	PublicKey string `db:"public_key" json:"public_key"`
	// 密钥创建时间
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// CommandFilterACL 命令过滤规则模型，定义 SSH 会话中允许或拒绝执行哪些命令
type CommandFilterACL struct {
	ID int64 `db:"id" json:"id"`
	// 规则名称，用于标识和展示
	Name string `db:"name" json:"name"`
	// 正则表达式模式，匹配 SSH 会话中执行的命令
	Pattern string `db:"pattern" json:"pattern"`
	// 规则动作：allow 放行，deny 拒绝
	Action string `db:"action" json:"action"`
	// 规则创建时间
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
