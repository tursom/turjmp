// 包 repository 提供系统初始化与默认数据种子功能。
//
// 启动时按顺序自动创建默认数据：角色 → 平台 → 根节点 → 系统设置 → 管理员用户。
// 所有操作均为幂等（已存在则跳过），确保可安全重复执行。
package repository

import (
	"errors"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
)

// DefaultSetting 定义一条系统默认设置的结构，包含键、值、分类、标签、描述、控件类型和选项列表。
type DefaultSetting struct {
	Key         string
	Value       string
	Category    string
	Label       string
	Description string
	InputType   string
	Options     string
}

// BootstrapDefaults 执行系统初始化，按顺序创建默认角色、平台、根节点、系统设置和管理员账户。
// 所有操作均为幂等：已存在的数据会被跳过，不会重复创建。
func (s *Store) BootstrapDefaults() error {
	for _, role := range defaultRoles {
		if _, err := s.UpsertRole(role.name, role.description); err != nil {
			return err
		}
	}
	for _, platform := range defaultPlatforms {
		p, err := s.UpsertPlatform(platform.name, platform.typ, platform.description)
		if err != nil {
			return err
		}
		if err := s.UpsertPlatformProtocol(p.ID, platform.protocol, platform.port); err != nil {
			return err
		}
	}
	if err := s.EnsureRootNode(); err != nil {
		return err
	}
	for _, setting := range DefaultSettings() {
		if _, err := s.GetSetting(setting.Key); err == nil {
			continue
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err := s.UpsertSetting(domain.Setting{
			Key:         setting.Key,
			Value:       setting.Value,
			Category:    setting.Category,
			Label:       setting.Label,
			Description: setting.Description,
			InputType:   setting.InputType,
			Options:     setting.Options,
		}); err != nil {
			return err
		}
	}
	return s.ensureAdmin()
}

// ensureAdmin 确保默认管理员账户（admin/admin123）存在，并赋予 super_admin 角色。
func (s *Store) ensureAdmin() error {
	if _, err := s.GetUserByUsername("admin"); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	hash, err := auth.HashPassword("admin123")
	if err != nil {
		return err
	}
	user := domain.User{
		Username:     "admin",
		Name:         "Administrator",
		Email:        "admin@turjmp.local",
		PasswordHash: hash,
		IsActive:     true,
	}
	if err := s.CreateUser(&user); err != nil {
		return err
	}
	role, err := s.GetRoleByName("super_admin")
	if err != nil {
		return err
	}
	return s.SetUserRoles(user.ID, []int64{role.ID})
}

// 预定义的四种默认角色：超级管理员、管理员、运维操作员、审计员。
var defaultRoles = []struct {
	name        string
	description string
}{
	{"super_admin", "Full system administrator"},
	{"admin", "Administrator"},
	{"operator", "Asset operator"},
	{"auditor", "Session auditor"},
}

// 预定义的四种默认资产平台：Linux（SSH）、Windows（RDP）、MySQL、PostgreSQL。
var defaultPlatforms = []struct {
	name        string
	typ         string
	description string
	protocol    string
	port        int
}{
	{"Linux", "linux", "Linux server with SSH", "ssh", 22},
	{"Windows", "windows", "Windows server with RDP", "rdp", 3389},
	{"MySQL", "mysql", "MySQL database", "mysql", 3306},
	{"PostgreSQL", "postgres", "PostgreSQL database", "postgres", 5432},
}

// DefaultSettings 返回系统所有的默认设置项，覆盖管理控制台第一阶段暴露的主要配置分类。
func DefaultSettings() []DefaultSetting {
	return []DefaultSetting{
		{"recording.storage", `"local"`, "recording", "Recording Storage", "Recording storage backend", "select", `["local","s3","oss","cos"]`},
		{"recording.local.path", `"./recordings"`, "recording", "Local Recording Path", "Local recording directory", "text", ""},
		{"recording.s3.endpoint", `""`, "recording", "S3 Endpoint", "S3 or MinIO endpoint", "text", ""},
		{"recording.s3.bucket", `"turjmp-sessions"`, "recording", "S3 Bucket", "S3 bucket name", "text", ""},
		{"recording.s3.access_key", `""`, "recording", "S3 Access Key", "S3 access key", "secret", ""},
		{"recording.s3.secret_key", `""`, "recording", "S3 Secret Key", "S3 secret key", "secret", ""},
		{"recording.oss.endpoint", `""`, "recording", "OSS Endpoint", "OSS endpoint", "text", ""},
		{"recording.oss.bucket", `""`, "recording", "OSS Bucket", "OSS bucket name", "text", ""},
		{"recording.oss.access_key", `""`, "recording", "OSS Access Key", "OSS access key", "secret", ""},
		{"recording.oss.secret_key", `""`, "recording", "OSS Secret Key", "OSS secret key", "secret", ""},
		{"proxy.ssh.max_connections", `100`, "proxy", "SSH Max Connections", "Maximum concurrent SSH connections", "number", ""},
		{"proxy.ssh.idle_timeout", `900`, "proxy", "SSH Idle Timeout", "SSH idle timeout in seconds", "number", ""},
		{"proxy.db.max_connections", `50`, "proxy", "DB Max Connections", "Maximum concurrent DB proxy connections", "number", ""},
		{"proxy.db.idle_timeout", `1800`, "proxy", "DB Idle Timeout", "DB idle timeout in seconds", "number", ""},
		{"proxy.rdp.max_connections", `20`, "proxy", "RDP Max Connections", "Maximum concurrent RDP connections", "number", ""},
		{"proxy.rdp.idle_timeout", `3600`, "proxy", "RDP Idle Timeout", "RDP idle timeout in seconds", "number", ""},
		{"proxy.session.max_duration", `3600`, "proxy", "Session Max Duration", "Maximum session duration in seconds", "number", ""},
		{"security.session_timeout", `3600`, "security", "Session Timeout", "Maximum session duration in seconds", "number", ""},
		{"security.mfa_required", `false`, "security", "MFA Required", "Require MFA for all users", "toggle", ""},
		{"security.password_min_length", `8`, "security", "Password Min Length", "Minimum password length", "number", ""},
		{"security.login_failure_lock_enabled", `true`, "security", "Login Failure Lock", "Lock users after repeated login failures", "toggle", ""},
		{"security.login_failure_threshold", `5`, "security", "Login Failure Threshold", "Failed login attempts before locking", "number", ""},
		{"security.login_failure_lock_minutes", `15`, "security", "Login Failure Lock Minutes", "Lock duration after repeated failures", "number", ""},
		{"sftp.max_file_size", `1073741824`, "sftp", "SFTP Max File Size", "Maximum SFTP file size", "number", ""},
		{"sftp.deny_paths", `"/etc/shadow,/etc/passwd"`, "sftp", "SFTP Deny Paths", "Denied SFTP paths", "text", ""},
		{"notification.smtp.host", `""`, "notification", "SMTP Host", "SMTP host", "text", ""},
		{"notification.smtp.port", `587`, "notification", "SMTP Port", "SMTP server port", "number", ""},
		{"notification.smtp.username", `""`, "notification", "SMTP Username", "SMTP username", "text", ""},
		{"notification.smtp.password", `""`, "notification", "SMTP Password", "SMTP password", "secret", ""},
		{"notification.smtp.from", `""`, "notification", "SMTP From", "Default sender address", "text", ""},
		{"notification.email.template", `""`, "notification", "Email Template", "Default notification email template", "text", ""},
		{"branding.site_name", `"Turjmp"`, "branding", "Site Name", "Visible site name", "text", ""},
		{"branding.logo_url", `""`, "branding", "Logo URL", "Custom logo URL", "text", ""},
		{"branding.theme_color", `"#2563eb"`, "branding", "Theme Color", "Primary theme color", "text", ""},
		{"auth.ldap.enabled", `false`, "auth", "LDAP Enabled", "Enable LDAP authentication", "toggle", ""},
		{"auth.ldap.url", `""`, "auth", "LDAP URL", "LDAP server URL", "text", ""},
		{"auth.ldap.bind_dn", `""`, "auth", "LDAP Bind DN", "LDAP bind distinguished name", "text", ""},
		{"auth.ldap.bind_password", `""`, "auth", "LDAP Bind Password", "LDAP bind password", "secret", ""},
		{"auth.ldap.user_search_base", `""`, "auth", "LDAP User Search Base", "LDAP user search base DN", "text", ""},
		{"auth.oauth.enabled", `false`, "auth", "OAuth Enabled", "Enable OAuth authentication", "toggle", ""},
		{"auth.oauth.client_id", `""`, "auth", "OAuth Client ID", "OAuth client ID", "text", ""},
		{"auth.oauth.client_secret", `""`, "auth", "OAuth Client Secret", "OAuth client secret", "secret", ""},
		{"auth.oauth.auth_url", `""`, "auth", "OAuth Auth URL", "OAuth authorization endpoint", "text", ""},
		{"auth.oauth.token_url", `""`, "auth", "OAuth Token URL", "OAuth token endpoint", "text", ""},
		{"auth.oauth.scopes", `"openid,profile,email"`, "auth", "OAuth Scopes", "OAuth scopes, comma-separated", "text", ""},
	}
}
