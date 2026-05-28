package domain

import "time"

type User struct {
	ID           int64      `db:"id" json:"id"`
	Username     string     `db:"username" json:"username"`
	Name         string     `db:"name" json:"name"`
	Email        string     `db:"email" json:"email"`
	PasswordHash string     `db:"password_hash" json:"-"`
	MFAEnabled   bool       `db:"mfa_enabled" json:"mfa_enabled"`
	MFASecret    string     `db:"mfa_secret" json:"-"`
	IsActive     bool       `db:"is_active" json:"is_active"`
	LastLoginAt  *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}

type Role struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type UserGroup struct {
	ID        int64     `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	OrgID     int64     `db:"org_id" json:"org_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type Platform struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Type        string    `db:"type" json:"type"`
	Description string    `db:"description" json:"description"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type PlatformProtocol struct {
	ID         int64     `db:"id" json:"id"`
	PlatformID int64     `db:"platform_id" json:"platform_id"`
	Name       string    `db:"name" json:"name"`
	Port       int       `db:"port" json:"port"`
	Settings   string    `db:"settings" json:"settings"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

type Node struct {
	ID        int64     `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	ParentID  *int64    `db:"parent_id" json:"parent_id,omitempty"`
	OrgID     int64     `db:"org_id" json:"org_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type Asset struct {
	ID         int64     `db:"id" json:"id"`
	Name       string    `db:"name" json:"name"`
	Address    string    `db:"address" json:"address"`
	PlatformID int64     `db:"platform_id" json:"platform_id"`
	NodeID     *int64    `db:"node_id" json:"node_id,omitempty"`
	Comment    string    `db:"comment" json:"comment"`
	IsActive   bool      `db:"is_active" json:"is_active"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

type AssetWithPlatform struct {
	Asset
	PlatformName string `db:"platform_name" json:"platform_name"`
	PlatformType string `db:"platform_type" json:"platform_type"`
}

type Account struct {
	ID          int64     `db:"id" json:"id"`
	AssetID     int64     `db:"asset_id" json:"asset_id"`
	Name        string    `db:"name" json:"name"`
	Username    string    `db:"username" json:"username"`
	Secret      string    `db:"secret" json:"-"`
	SecretType  string    `db:"secret_type" json:"secret_type"`
	SSHKeyType  string    `db:"ssh_key_type" json:"ssh_key_type"`
	Passphrase  string    `db:"passphrase" json:"-"`
	SUEnabled   bool      `db:"su_enabled" json:"su_enabled"`
	SUMethod    string    `db:"su_method" json:"su_method"`
	SUAccountID *int64    `db:"su_account_id" json:"su_account_id,omitempty"`
	DBName      string    `db:"db_name" json:"db_name"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type AssetPermission struct {
	ID          int64      `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`
	Actions     string     `db:"actions" json:"actions"`
	DateStart   *time.Time `db:"date_start" json:"date_start,omitempty"`
	DateExpired *time.Time `db:"date_expired" json:"date_expired,omitempty"`
	IsActive    bool       `db:"is_active" json:"is_active"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`
}

type ConnectionToken struct {
	ID             int64      `db:"id" json:"id"`
	Value          string     `db:"value" json:"value"`
	UserID         int64      `db:"user_id" json:"user_id"`
	AssetID        int64      `db:"asset_id" json:"asset_id"`
	AccountID      int64      `db:"account_id" json:"account_id"`
	Protocol       string     `db:"protocol" json:"protocol"`
	ConnectMethod  string     `db:"connect_method" json:"connect_method"`
	IsReusable     bool       `db:"is_reusable" json:"is_reusable"`
	ConnectOptions string     `db:"connect_options" json:"connect_options"`
	UsedAt         *time.Time `db:"used_at" json:"used_at,omitempty"`
	ExpiresAt      time.Time  `db:"expires_at" json:"expires_at"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}

type Session struct {
	ID            int64      `db:"id" json:"id"`
	UserID        int64      `db:"user_id" json:"user_id"`
	AssetID       int64      `db:"asset_id" json:"asset_id"`
	AccountID     int64      `db:"account_id" json:"account_id"`
	Protocol      string     `db:"protocol" json:"protocol"`
	Type          string     `db:"type" json:"type"`
	LoginFrom     string     `db:"login_from" json:"login_from"`
	RemoteAddr    string     `db:"remote_addr" json:"remote_addr"`
	RecordingPath string     `db:"recording_path" json:"recording_path"`
	IsFinished    bool       `db:"is_finished" json:"is_finished"`
	DateStart     time.Time  `db:"date_start" json:"date_start"`
	DateEnd       *time.Time `db:"date_end" json:"date_end,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
}

type Setting struct {
	Key         string    `db:"key" json:"key"`
	Value       string    `db:"value" json:"value"`
	Category    string    `db:"category" json:"category"`
	Label       string    `db:"label" json:"label"`
	Description string    `db:"description" json:"description"`
	InputType   string    `db:"input_type" json:"input_type"`
	Options     string    `db:"options" json:"options"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type RefreshToken struct {
	ID        string     `db:"id" json:"id"`
	UserID    int64      `db:"user_id" json:"user_id"`
	TokenHash string     `db:"token_hash" json:"-"`
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

type AuditLog struct {
	ID         int64     `db:"id" json:"id"`
	UserID     *int64    `db:"user_id" json:"user_id,omitempty"`
	Action     string    `db:"action" json:"action"`
	Resource   string    `db:"resource" json:"resource"`
	RemoteAddr string    `db:"remote_addr" json:"remote_addr"`
	Detail     string    `db:"detail" json:"detail"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}
