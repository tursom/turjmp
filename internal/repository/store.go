package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/tursom/turjmp/internal/domain"
)

type Store struct {
	db *DB
}

func NewStore(db *DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *DB {
	return s.db
}

func (s *Store) query(q string) string {
	return s.db.Rebind(q)
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func (s *Store) CreateUser(u *domain.User) error {
	q := s.query(`INSERT INTO users (username, name, email, password_hash, mfa_enabled, mfa_secret, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(u, q, u.Username, u.Name, u.Email, u.PasswordHash, u.MFAEnabled, u.MFASecret, u.IsActive))
}

func (s *Store) UpdateUser(u *domain.User) error {
	q := s.query(`UPDATE users SET username = ?, name = ?, email = ?, password_hash = ?, mfa_enabled = ?,
		mfa_secret = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(u, q, u.Username, u.Name, u.Email, u.PasswordHash, u.MFAEnabled, u.MFASecret, u.IsActive, u.ID))
}

func (s *Store) TouchUserLogin(userID int64) error {
	_, err := s.db.Exec(s.query(`UPDATE users SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), userID)
	return err
}

func (s *Store) GetUser(id int64) (domain.User, error) {
	var u domain.User
	err := s.db.Get(&u, s.query(`SELECT * FROM users WHERE id = ?`), id)
	return u, notFound(err)
}

func (s *Store) GetUserByUsername(username string) (domain.User, error) {
	var u domain.User
	err := s.db.Get(&u, s.query(`SELECT * FROM users WHERE username = ?`), username)
	return u, notFound(err)
}

func (s *Store) ListUsers() ([]domain.User, error) {
	var users []domain.User
	err := s.db.Select(&users, `SELECT * FROM users ORDER BY id`)
	return users, err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM users WHERE id = ?`), id)
	return err
}

func (s *Store) CreateRole(r *domain.Role) error {
	q := s.query(`INSERT INTO roles (name, description) VALUES (?, ?) RETURNING *`)
	return notFound(s.db.Get(r, q, r.Name, r.Description))
}

func (s *Store) UpsertRole(name, description string) (domain.Role, error) {
	if r, err := s.GetRoleByName(name); err == nil {
		if r.Description != description {
			r.Description = description
			_ = s.UpdateRole(&r)
		}
		return r, nil
	}
	r := domain.Role{Name: name, Description: description}
	return r, s.CreateRole(&r)
}

func (s *Store) UpdateRole(r *domain.Role) error {
	q := s.query(`UPDATE roles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(r, q, r.Name, r.Description, r.ID))
}

func (s *Store) GetRole(id int64) (domain.Role, error) {
	var r domain.Role
	err := s.db.Get(&r, s.query(`SELECT * FROM roles WHERE id = ?`), id)
	return r, notFound(err)
}

func (s *Store) GetRoleByName(name string) (domain.Role, error) {
	var r domain.Role
	err := s.db.Get(&r, s.query(`SELECT * FROM roles WHERE name = ?`), name)
	return r, notFound(err)
}

func (s *Store) ListRoles() ([]domain.Role, error) {
	var roles []domain.Role
	err := s.db.Select(&roles, `SELECT * FROM roles ORDER BY id`)
	return roles, err
}

func (s *Store) DeleteRole(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM roles WHERE id = ?`), id)
	return err
}

func (s *Store) SetUserRoles(userID int64, roleIDs []int64) error {
	return withTx(s.db.DB, func(tx *sqlx.Tx) error {
		if _, err := tx.Exec(s.query(`DELETE FROM user_roles WHERE user_id = ?`), userID); err != nil {
			return err
		}
		for _, roleID := range roleIDs {
			if _, err := tx.Exec(s.query(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`), userID, roleID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) UserRoles(userID int64) ([]domain.Role, error) {
	var roles []domain.Role
	q := s.query(`SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.id`)
	err := s.db.Select(&roles, q, userID)
	return roles, err
}

func (s *Store) UserRoleNames(userID int64) ([]string, error) {
	roles, err := s.UserRoles(userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names, nil
}

func (s *Store) CreateRefreshToken(t domain.RefreshToken) error {
	_, err := s.db.Exec(s.query(`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`),
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt)
	return err
}

func (s *Store) GetRefreshTokenByHash(hash string) (domain.RefreshToken, error) {
	var t domain.RefreshToken
	err := s.db.Get(&t, s.query(`SELECT * FROM refresh_tokens WHERE token_hash = ?`), hash)
	return t, notFound(err)
}

func (s *Store) RevokeRefreshToken(id string) error {
	_, err := s.db.Exec(s.query(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL`), id)
	return err
}

func (s *Store) RevokeUserRefreshTokens(userID int64) error {
	_, err := s.db.Exec(s.query(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL`), userID)
	return err
}

func (s *Store) UpsertPlatform(name, typ, description string) (domain.Platform, error) {
	var p domain.Platform
	err := s.db.Get(&p, s.query(`SELECT * FROM platforms WHERE name = ?`), name)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return p, err
	}
	err = s.db.Get(&p, s.query(`INSERT INTO platforms (name, type, description) VALUES (?, ?, ?) RETURNING *`), name, typ, description)
	return p, err
}

func (s *Store) UpsertPlatformProtocol(platformID int64, name string, port int) error {
	var id int64
	err := s.db.Get(&id, s.query(`SELECT id FROM platform_protocols WHERE platform_id = ? AND name = ?`), platformID, name)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.Exec(s.query(`INSERT INTO platform_protocols (platform_id, name, port) VALUES (?, ?, ?)`), platformID, name, port)
	return err
}

func (s *Store) ListPlatforms() ([]domain.Platform, error) {
	var platforms []domain.Platform
	err := s.db.Select(&platforms, `SELECT * FROM platforms ORDER BY id`)
	return platforms, err
}

func (s *Store) ListPlatformProtocols(platformID int64) ([]domain.PlatformProtocol, error) {
	var protocols []domain.PlatformProtocol
	err := s.db.Select(&protocols, s.query(`SELECT * FROM platform_protocols WHERE platform_id = ? ORDER BY id`), platformID)
	return protocols, err
}

func (s *Store) EnsureRootNode() error {
	var id int64
	err := s.db.Get(&id, `SELECT id FROM nodes WHERE parent_id IS NULL ORDER BY id LIMIT 1`)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO nodes (name, org_id) VALUES ('Default', 1)`)
	return err
}

func (s *Store) CreateAsset(a *domain.Asset) error {
	q := s.query(`INSERT INTO assets (name, address, platform_id, node_id, comment, is_active)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Address, a.PlatformID, a.NodeID, a.Comment, a.IsActive))
}

func (s *Store) UpdateAsset(a *domain.Asset) error {
	q := s.query(`UPDATE assets SET name = ?, address = ?, platform_id = ?, node_id = ?, comment = ?,
		is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Address, a.PlatformID, a.NodeID, a.Comment, a.IsActive, a.ID))
}

func (s *Store) GetAsset(id int64) (domain.Asset, error) {
	var a domain.Asset
	err := s.db.Get(&a, s.query(`SELECT * FROM assets WHERE id = ?`), id)
	return a, notFound(err)
}

// GetAssetProtocolPort 通过资产关联的平台协议配置，查询指定协议对应的端口号
// 查询逻辑：JOIN platform_protocols 表，根据 asset_id 和 protocol name 获取端口
func (s *Store) GetAssetProtocolPort(assetID int64, protocol string) (int, error) {
	var port int
	err := s.db.Get(&port, s.query(`SELECT pp.port
		FROM assets a
		JOIN platform_protocols pp ON pp.platform_id = a.platform_id
		WHERE a.id = ? AND pp.name = ?
		LIMIT 1`), assetID, protocol)
	return port, notFound(err)
}

func (s *Store) ListAssets() ([]domain.AssetWithPlatform, error) {
	var assets []domain.AssetWithPlatform
	err := s.db.Select(&assets, `SELECT a.*, p.name AS platform_name, p.type AS platform_type
		FROM assets a JOIN platforms p ON p.id = a.platform_id ORDER BY a.id`)
	return assets, err
}

func (s *Store) DeleteAsset(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM assets WHERE id = ?`), id)
	return err
}

func (s *Store) ListNodes() ([]domain.Node, error) {
	var nodes []domain.Node
	err := s.db.Select(&nodes, `SELECT * FROM nodes ORDER BY id`)
	return nodes, err
}

func (s *Store) CreateAccount(a *domain.Account) error {
	q := s.query(`INSERT INTO accounts (asset_id, name, username, secret, secret_type, ssh_key_type, passphrase,
		su_enabled, su_method, su_account_id, db_name, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(a, q, a.AssetID, a.Name, a.Username, a.Secret, a.SecretType, a.SSHKeyType, a.Passphrase,
		a.SUEnabled, a.SUMethod, a.SUAccountID, a.DBName, a.IsActive))
}

func (s *Store) UpdateAccount(a *domain.Account) error {
	q := s.query(`UPDATE accounts SET name = ?, username = ?, secret = ?, secret_type = ?, ssh_key_type = ?,
		passphrase = ?, su_enabled = ?, su_method = ?, su_account_id = ?, db_name = ?, is_active = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ? AND asset_id = ? RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Username, a.Secret, a.SecretType, a.SSHKeyType, a.Passphrase,
		a.SUEnabled, a.SUMethod, a.SUAccountID, a.DBName, a.IsActive, a.ID, a.AssetID))
}

func (s *Store) GetAccount(id int64) (domain.Account, error) {
	var a domain.Account
	err := s.db.Get(&a, s.query(`SELECT * FROM accounts WHERE id = ?`), id)
	return a, notFound(err)
}

func (s *Store) GetAssetAccount(assetID, accountID int64) (domain.Account, error) {
	var a domain.Account
	err := s.db.Get(&a, s.query(`SELECT * FROM accounts WHERE id = ? AND asset_id = ?`), accountID, assetID)
	return a, notFound(err)
}

func (s *Store) ListAccounts(assetID int64) ([]domain.Account, error) {
	var accounts []domain.Account
	err := s.db.Select(&accounts, s.query(`SELECT * FROM accounts WHERE asset_id = ? ORDER BY id`), assetID)
	return accounts, err
}

func (s *Store) DeleteAccount(assetID, accountID int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM accounts WHERE id = ? AND asset_id = ?`), accountID, assetID)
	return err
}

type PermissionLinks struct {
	UserIDs    []int64 `json:"user_ids"`
	GroupIDs   []int64 `json:"group_ids"`
	AssetIDs   []int64 `json:"asset_ids"`
	NodeIDs    []int64 `json:"node_ids"`
	AccountIDs []int64 `json:"account_ids"`
}

func (s *Store) CreatePermission(p *domain.AssetPermission, links PermissionLinks) error {
	return withTx(s.db.DB, func(tx *sqlx.Tx) error {
		q := s.query(`INSERT INTO asset_permissions (name, actions, date_start, date_expired, is_active)
			VALUES (?, ?, ?, ?, ?) RETURNING *`)
		if err := tx.Get(p, q, p.Name, p.Actions, p.DateStart, p.DateExpired, p.IsActive); err != nil {
			return err
		}
		return insertPermissionLinks(tx, s.query, p.ID, links)
	})
}

func (s *Store) UpdatePermission(p *domain.AssetPermission, links PermissionLinks) error {
	return withTx(s.db.DB, func(tx *sqlx.Tx) error {
		q := s.query(`UPDATE asset_permissions SET name = ?, actions = ?, date_start = ?, date_expired = ?,
			is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
		if err := tx.Get(p, q, p.Name, p.Actions, p.DateStart, p.DateExpired, p.IsActive, p.ID); err != nil {
			return err
		}
		for _, table := range []string{"perm_users", "perm_user_groups", "perm_assets", "perm_nodes", "perm_accounts"} {
			if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE permission_id = ?", table), p.ID); err != nil {
				return err
			}
		}
		return insertPermissionLinks(tx, s.query, p.ID, links)
	})
}

func insertPermissionLinks(tx *sqlx.Tx, rebind func(string) string, permissionID int64, links PermissionLinks) error {
	for _, id := range links.UserIDs {
		if _, err := tx.Exec(rebind(`INSERT INTO perm_users (permission_id, user_id) VALUES (?, ?)`), permissionID, id); err != nil {
			return err
		}
	}
	for _, id := range links.GroupIDs {
		if _, err := tx.Exec(rebind(`INSERT INTO perm_user_groups (permission_id, group_id) VALUES (?, ?)`), permissionID, id); err != nil {
			return err
		}
	}
	for _, id := range links.AssetIDs {
		if _, err := tx.Exec(rebind(`INSERT INTO perm_assets (permission_id, asset_id) VALUES (?, ?)`), permissionID, id); err != nil {
			return err
		}
	}
	for _, id := range links.NodeIDs {
		if _, err := tx.Exec(rebind(`INSERT INTO perm_nodes (permission_id, node_id) VALUES (?, ?)`), permissionID, id); err != nil {
			return err
		}
	}
	for _, id := range links.AccountIDs {
		if _, err := tx.Exec(rebind(`INSERT INTO perm_accounts (permission_id, account_id) VALUES (?, ?)`), permissionID, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetPermission(id int64) (domain.AssetPermission, PermissionLinks, error) {
	var p domain.AssetPermission
	if err := s.db.Get(&p, s.query(`SELECT * FROM asset_permissions WHERE id = ?`), id); err != nil {
		return p, PermissionLinks{}, notFound(err)
	}
	links, err := s.PermissionLinks(id)
	return p, links, err
}

func (s *Store) ListPermissions() ([]domain.AssetPermission, error) {
	var permissions []domain.AssetPermission
	err := s.db.Select(&permissions, `SELECT * FROM asset_permissions ORDER BY id`)
	return permissions, err
}

func (s *Store) PermissionLinks(permissionID int64) (PermissionLinks, error) {
	var links PermissionLinks
	if err := s.db.Select(&links.UserIDs, s.query(`SELECT user_id FROM perm_users WHERE permission_id = ?`), permissionID); err != nil {
		return links, err
	}
	if err := s.db.Select(&links.GroupIDs, s.query(`SELECT group_id FROM perm_user_groups WHERE permission_id = ?`), permissionID); err != nil {
		return links, err
	}
	if err := s.db.Select(&links.AssetIDs, s.query(`SELECT asset_id FROM perm_assets WHERE permission_id = ?`), permissionID); err != nil {
		return links, err
	}
	if err := s.db.Select(&links.NodeIDs, s.query(`SELECT node_id FROM perm_nodes WHERE permission_id = ?`), permissionID); err != nil {
		return links, err
	}
	if err := s.db.Select(&links.AccountIDs, s.query(`SELECT account_id FROM perm_accounts WHERE permission_id = ?`), permissionID); err != nil {
		return links, err
	}
	return links, nil
}

func (s *Store) DeletePermission(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM asset_permissions WHERE id = ?`), id)
	return err
}

func (s *Store) HasAssetPermission(userID, assetID, accountID int64, action string) (bool, error) {
	var n int
	q := s.query(`SELECT COUNT(1)
		FROM asset_permissions p
		JOIN perm_users pu ON pu.permission_id = p.id AND pu.user_id = ?
		JOIN perm_assets pa ON pa.permission_id = p.id AND pa.asset_id = ?
		WHERE p.is_active = ?
		  AND (p.date_start IS NULL OR p.date_start <= CURRENT_TIMESTAMP)
		  AND (p.date_expired IS NULL OR p.date_expired > CURRENT_TIMESTAMP)
		  AND (',' || p.actions || ',') LIKE ?
		  AND (
		    EXISTS (SELECT 1 FROM perm_accounts pac WHERE pac.permission_id = p.id AND pac.account_id = ?)
		    OR NOT EXISTS (SELECT 1 FROM perm_accounts pac2 WHERE pac2.permission_id = p.id)
		  )`)
	err := s.db.Get(&n, q, userID, assetID, true, "%,"+action+",%", accountID)
	return n > 0, err
}

func (s *Store) CreateConnectionToken(t *domain.ConnectionToken) error {
	q := s.query(`INSERT INTO connection_tokens (value, user_id, asset_id, account_id, protocol, connect_method,
		is_reusable, connect_options, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(t, q, t.Value, t.UserID, t.AssetID, t.AccountID, t.Protocol, t.ConnectMethod,
		t.IsReusable, t.ConnectOptions, t.ExpiresAt))
}

func (s *Store) GetConnectionToken(value string) (domain.ConnectionToken, error) {
	var t domain.ConnectionToken
	err := s.db.Get(&t, s.query(`SELECT * FROM connection_tokens WHERE value = ?`), value)
	return t, notFound(err)
}

func (s *Store) MarkConnectionTokenUsed(value string) error {
	_, err := s.db.Exec(s.query(`UPDATE connection_tokens SET used_at = CURRENT_TIMESTAMP WHERE value = ?`), value)
	return err
}

func (s *Store) CreateSession(sess *domain.Session) error {
	q := s.query(`INSERT INTO sessions (user_id, asset_id, account_id, protocol, type, login_from, remote_addr,
		recording_path, is_finished)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(sess, q, sess.UserID, sess.AssetID, sess.AccountID, sess.Protocol, sess.Type,
		sess.LoginFrom, sess.RemoteAddr, sess.RecordingPath, sess.IsFinished))
}

func (s *Store) UpdateSession(sess *domain.Session) error {
	q := s.query(`UPDATE sessions SET is_finished = ?, date_end = ?, recording_path = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(sess, q, sess.IsFinished, sess.DateEnd, sess.RecordingPath, sess.ID))
}

func (s *Store) GetSession(id int64) (domain.Session, error) {
	var sess domain.Session
	err := s.db.Get(&sess, s.query(`SELECT * FROM sessions WHERE id = ?`), id)
	return sess, notFound(err)
}

func (s *Store) ListSessions() ([]domain.Session, error) {
	var sessions []domain.Session
	err := s.db.Select(&sessions, `SELECT * FROM sessions ORDER BY id DESC`)
	return sessions, err
}

func (s *Store) UpsertSetting(setting domain.Setting) error {
	if s.db.Driver == "postgres" {
		_, err := s.db.Exec(`INSERT INTO settings (key, value, category, label, description, input_type, options)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, category = EXCLUDED.category,
			label = EXCLUDED.label, description = EXCLUDED.description, input_type = EXCLUDED.input_type,
			options = EXCLUDED.options, updated_at = CURRENT_TIMESTAMP`,
			setting.Key, setting.Value, setting.Category, setting.Label, setting.Description, setting.InputType, setting.Options)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings (key, value, category, label, description, input_type, options)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, category = excluded.category,
		label = excluded.label, description = excluded.description, input_type = excluded.input_type,
		options = excluded.options, updated_at = CURRENT_TIMESTAMP`,
		setting.Key, setting.Value, setting.Category, setting.Label, setting.Description, setting.InputType, setting.Options)
	return err
}

func (s *Store) GetSetting(key string) (domain.Setting, error) {
	var setting domain.Setting
	err := s.db.Get(&setting, s.query(`SELECT * FROM settings WHERE key = ?`), key)
	return setting, notFound(err)
}

func (s *Store) ListSettings() ([]domain.Setting, error) {
	var settings []domain.Setting
	err := s.db.Select(&settings, `SELECT * FROM settings ORDER BY category, key`)
	return settings, err
}

func (s *Store) ListAuditLogs() ([]domain.AuditLog, error) {
	var logs []domain.AuditLog
	err := s.db.Select(&logs, `SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200`)
	return logs, err
}

func (s *Store) Audit(userID *int64, action, resource, remoteAddr, detail string) error {
	_, err := s.db.Exec(s.query(`INSERT INTO audit_logs (user_id, action, resource, remote_addr, detail)
		VALUES (?, ?, ?, ?, ?)`), userID, action, resource, remoteAddr, detail)
	return err
}

// ListHostKeys 查询所有 SSH 主机密钥记录，按 ID 排序
func (s *Store) ListHostKeys() ([]domain.HostKey, error) {
	var keys []domain.HostKey
	err := s.db.Select(&keys, `SELECT * FROM host_keys ORDER BY id`)
	return keys, err
}

// GetHostKeyByAlgorithm 按算法名称（如 ssh-ed25519、ssh-rsa）查询主机密钥记录
// 若存在多条同算法记录，取 ID 最小的第一条
func (s *Store) GetHostKeyByAlgorithm(algorithm string) (domain.HostKey, error) {
	var key domain.HostKey
	err := s.db.Get(&key, s.query(`SELECT * FROM host_keys WHERE algorithm = ? ORDER BY id LIMIT 1`), algorithm)
	return key, notFound(err)
}

// CreateHostKey 创建一条新的 SSH 主机密钥记录
// 存储算法名称、SHA256 指纹、PEM 格式私钥和 OpenSSH 格式公钥
func (s *Store) CreateHostKey(key *domain.HostKey) error {
	q := s.query(`INSERT INTO host_keys (algorithm, fingerprint, private_key, public_key)
		VALUES (?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(key, q, key.Algorithm, key.Fingerprint, key.PrivateKey, key.PublicKey))
}

// ListCommandFilterACLs 查询所有命令过滤 ACL 规则，按 ID 排序
// 这些规则供 SSH 代理组件用于拦截或放行用户在跳板机上执行的命令
func (s *Store) ListCommandFilterACLs() ([]domain.CommandFilterACL, error) {
	var rules []domain.CommandFilterACL
	err := s.db.Select(&rules, `SELECT * FROM command_filter_acls ORDER BY id`)
	return rules, err
}

func withTx(db *sqlx.DB, fn func(*sqlx.Tx) error) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func NormalizeActions(actions []string) string {
	if len(actions) == 0 {
		return "connect"
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		out = append(out, action)
	}
	if len(out) == 0 {
		return "connect"
	}
	return strings.Join(out, ",")
}

func NowPtr() *time.Time {
	now := time.Now().UTC()
	return &now
}
