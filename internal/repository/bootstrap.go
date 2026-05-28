package repository

import (
	"errors"

	"github.com/tursom/turjmp/internal/auth"
	"github.com/tursom/turjmp/internal/domain"
)

type DefaultSetting struct {
	Key         string
	Value       string
	Category    string
	Label       string
	Description string
	InputType   string
	Options     string
}

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

var defaultRoles = []struct {
	name        string
	description string
}{
	{"super_admin", "Full system administrator"},
	{"admin", "Administrator"},
	{"operator", "Asset operator"},
	{"auditor", "Session auditor"},
}

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

func DefaultSettings() []DefaultSetting {
	return []DefaultSetting{
		{"recording.storage", `"local"`, "recording", "Recording Storage", "Recording storage backend", "select", `["local","s3","oss","cos"]`},
		{"recording.local.path", `"./recordings"`, "recording", "Local Recording Path", "Local recording directory", "text", ""},
		{"recording.s3.endpoint", `""`, "recording", "S3 Endpoint", "S3 or MinIO endpoint", "text", ""},
		{"recording.s3.bucket", `"turjmp-sessions"`, "recording", "S3 Bucket", "S3 bucket name", "text", ""},
		{"recording.s3.access_key", `""`, "recording", "S3 Access Key", "S3 access key", "secret", ""},
		{"recording.s3.secret_key", `""`, "recording", "S3 Secret Key", "S3 secret key", "secret", ""},
		{"proxy.ssh.max_connections", `100`, "proxy", "SSH Max Connections", "Maximum concurrent SSH connections", "number", ""},
		{"proxy.ssh.idle_timeout", `900`, "proxy", "SSH Idle Timeout", "SSH idle timeout in seconds", "number", ""},
		{"proxy.db.max_connections", `50`, "proxy", "DB Max Connections", "Maximum concurrent DB proxy connections", "number", ""},
		{"proxy.db.idle_timeout", `1800`, "proxy", "DB Idle Timeout", "DB idle timeout in seconds", "number", ""},
		{"proxy.rdp.max_connections", `20`, "proxy", "RDP Max Connections", "Maximum concurrent RDP connections", "number", ""},
		{"security.session_timeout", `3600`, "security", "Session Timeout", "Maximum session duration in seconds", "number", ""},
		{"security.mfa_required", `false`, "security", "MFA Required", "Require MFA for all users", "toggle", ""},
		{"security.password_min_length", `8`, "security", "Password Min Length", "Minimum password length", "number", ""},
		{"sftp.max_file_size", `1073741824`, "sftp", "SFTP Max File Size", "Maximum SFTP file size", "number", ""},
		{"sftp.deny_paths", `"/etc/shadow,/etc/passwd"`, "sftp", "SFTP Deny Paths", "Denied SFTP paths", "text", ""},
		{"notification.smtp.host", `""`, "notification", "SMTP Host", "SMTP host", "text", ""},
		{"branding.site_name", `"Turjmp"`, "branding", "Site Name", "Visible site name", "text", ""},
	}
}
