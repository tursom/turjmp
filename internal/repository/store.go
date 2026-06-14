// 包 repository 提供持久化存储层，封装所有数据库 CRUD 操作。
//
// Store 是核心数据访问对象，统一管理用户、角色、资产、账号、权限、会话、刷新令牌等实体的持久化。
// SQL 模式：INSERT/UPDATE 使用 RETURNING * 返回完整记录，SELECT 返回后经 notFound 包装将 sql.ErrNoRows 转为 domain.ErrNotFound。
// 写操作通过 withTx 事务包装，确保多表操作的原子性。
// 占位符经由 Rebind 方法按数据库驱动（PostgreSQL: $N，SQLite: ?）自动适配。
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/tursom/turjmp/internal/domain"
)

// Store 是数据库持久化操作的统一入口，通过 sqlx 执行所有 CRUD 操作。
type Store struct {
	db *DB
}

// AuditLogFilter describes server-side filtering and pagination for audit logs.
type AuditLogFilter struct {
	Search   string
	UserID   int64
	Action   string
	DateFrom *time.Time
	DateTo   *time.Time
	Limit    int
	Offset   int
}

// DashboardSummary 聚合仪表盘首页所需的轻量统计。
type DashboardSummary struct {
	TotalAssets    int
	ActiveSessions int
	TodaySessions  int
	ActiveUsers    int
	RecentSessions []domain.SessionSummary
}

// NewStore 创建 Store 实例。
func NewStore(db *DB) *Store {
	return &Store{db: db}
}

// DB 返回底层 DB 实例，供 Casbin Adapter 等需要直接访问数据库的组件使用。
func (s *Store) DB() *DB {
	return s.db
}

// query 对 SQL 语句执行 Rebind 占位符转换，适配不同数据库驱动。
func (s *Store) query(q string) string {
	return s.db.Rebind(q)
}

// notFound 将 sql.ErrNoRows 转换为 domain.ErrNotFound，其他错误原样返回。
// 用于 Get 类方法中对 sqlx 查询结果的统一错误处理。
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

// CreateUser 创建新用户，INSERT 后通过 RETURNING * 将生成的 ID 和默认值写回传入的 User 结构体。
func (s *Store) CreateUser(u *domain.User) error {
	q := s.query(`INSERT INTO users (username, name, email, password_hash, mfa_enabled, mfa_secret, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(u, q, u.Username, u.Name, u.Email, u.PasswordHash, u.MFAEnabled, u.MFASecret, u.IsActive))
}

// UpdateUser 更新用户所有字段（除密码哈希外），同时刷新 updated_at，使用 RETURNING * 将更新后的记录写回。
func (s *Store) UpdateUser(u *domain.User) error {
	q := s.query(`UPDATE users SET username = ?, name = ?, email = ?, password_hash = ?, mfa_enabled = ?,
		mfa_secret = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(u, q, u.Username, u.Name, u.Email, u.PasswordHash, u.MFAEnabled, u.MFASecret, u.IsActive, u.ID))
}

// TouchUserLogin 更新用户最近登录时间（last_login_at 和 updated_at），用于登录审计。
func (s *Store) TouchUserLogin(userID int64) error {
	_, err := s.db.Exec(s.query(`UPDATE users SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), userID)
	return err
}

// GetUser 按 ID 查询单个用户记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetUser(id int64) (domain.User, error) {
	var u domain.User
	err := s.db.Get(&u, s.query(`SELECT * FROM users WHERE id = ?`), id)
	return u, notFound(err)
}

// GetUserByUsername 按用户名查询单个用户记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetUserByUsername(username string) (domain.User, error) {
	var u domain.User
	err := s.db.Get(&u, s.query(`SELECT * FROM users WHERE username = ?`), username)
	return u, notFound(err)
}

// ListUsers 返回所有用户列表，按 ID 升序排列。
func (s *Store) ListUsers() ([]domain.User, error) {
	var users []domain.User
	err := s.db.Select(&users, `SELECT * FROM users ORDER BY id`)
	return users, err
}

// DeleteUser 按 ID 删除用户记录。
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM users WHERE id = ?`), id)
	return err
}

// CreateRole 创建新角色，INSERT 后通过 RETURNING * 返回完整记录。
func (s *Store) CreateRole(r *domain.Role) error {
	q := s.query(`INSERT INTO roles (name, description) VALUES (?, ?) RETURNING *`)
	return notFound(s.db.Get(r, q, r.Name, r.Description))
}

// UpsertRole 按名称创建或更新角色。若角色已存在且描述不一致则更新，否则直接返回现有角色。
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

// UpdateRole 更新角色名称和描述，同时刷新 updated_at，返回更新后的记录。
func (s *Store) UpdateRole(r *domain.Role) error {
	q := s.query(`UPDATE roles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(r, q, r.Name, r.Description, r.ID))
}

// GetRole 按 ID 查询角色，未找到时返回 domain.ErrNotFound。
func (s *Store) GetRole(id int64) (domain.Role, error) {
	var r domain.Role
	err := s.db.Get(&r, s.query(`SELECT * FROM roles WHERE id = ?`), id)
	return r, notFound(err)
}

// GetRoleByName 按名称查询角色，未找到时返回 domain.ErrNotFound。
func (s *Store) GetRoleByName(name string) (domain.Role, error) {
	var r domain.Role
	err := s.db.Get(&r, s.query(`SELECT * FROM roles WHERE name = ?`), name)
	return r, notFound(err)
}

// ListRoles 返回所有角色列表，按 ID 升序排列。
func (s *Store) ListRoles() ([]domain.Role, error) {
	var roles []domain.Role
	err := s.db.Select(&roles, `SELECT * FROM roles ORDER BY id`)
	return roles, err
}

// ListUserGroups 返回所有用户组列表，按 ID 升序排列。
func (s *Store) ListUserGroups() ([]domain.UserGroup, error) {
	var groups []domain.UserGroup
	err := s.db.Select(&groups, `SELECT * FROM user_groups ORDER BY id`)
	return groups, err
}

// DeleteRole 按 ID 删除角色记录。
func (s *Store) DeleteRole(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM roles WHERE id = ?`), id)
	return err
}

// SetUserRoles 在事务中原子性地设置用户角色：先清空原有角色关联，再逐一插入新的角色关联。
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

// UserRoles 查询用户关联的所有角色（通过 user_roles 中间表 JOIN）。
func (s *Store) UserRoles(userID int64) ([]domain.Role, error) {
	var roles []domain.Role
	q := s.query(`SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.id`)
	err := s.db.Select(&roles, q, userID)
	return roles, err
}

// UserRoleNames 返回用户的所有角色名称列表，供 JWT Claims 填充使用。
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

// CreateRefreshToken 存储一条 refresh token 记录，包含 ID、用户 ID、token 哈希和过期时间。
func (s *Store) CreateRefreshToken(t domain.RefreshToken) error {
	_, err := s.db.Exec(s.query(`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`),
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt)
	return err
}

// GetRefreshTokenByHash 按 SHA256 哈希查找 refresh token 记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetRefreshTokenByHash(hash string) (domain.RefreshToken, error) {
	var t domain.RefreshToken
	err := s.db.Get(&t, s.query(`SELECT * FROM refresh_tokens WHERE token_hash = ?`), hash)
	return t, notFound(err)
}

// RevokeRefreshToken 撤销单个 refresh token（设置 revoked_at 为当前时间），仅对尚未撤销的记录生效。
func (s *Store) RevokeRefreshToken(id string) error {
	result, err := s.db.Exec(s.query(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL`), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return domain.ErrUnauthorized
	}
	return nil
}

// RevokeUserRefreshTokens 撤销指定用户的所有未撤销 refresh token。
func (s *Store) RevokeUserRefreshTokens(userID int64) error {
	_, err := s.db.Exec(s.query(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL`), userID)
	return err
}

// UpsertPlatform 按名称创建或获取资产平台记录，已存在则直接返回。
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

// UpsertPlatformProtocol 按平台 ID 和协议名称创建协议端口关联，已存在则跳过。
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

// ListPlatforms 返回所有资产平台列表，按 ID 升序排列。
func (s *Store) ListPlatforms() ([]domain.Platform, error) {
	var platforms []domain.Platform
	err := s.db.Select(&platforms, `SELECT * FROM platforms ORDER BY id`)
	return platforms, err
}

// ListPlatformProtocols 返回指定平台关联的所有协议端口配置。
func (s *Store) ListPlatformProtocols(platformID int64) ([]domain.PlatformProtocol, error) {
	var protocols []domain.PlatformProtocol
	err := s.db.Select(&protocols, s.query(`SELECT * FROM platform_protocols WHERE platform_id = ? ORDER BY id`), platformID)
	return protocols, err
}

// EnsureRootNode 确保存在一个根节点（parent_id IS NULL），用于构建资产树形结构的顶层。
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

// CreateAsset 创建新资产记录，INSERT 后通过 RETURNING * 返回完整记录。
func (s *Store) CreateAsset(a *domain.Asset) error {
	q := s.query(`INSERT INTO assets (name, address, platform_id, node_id, comment, is_active)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Address, a.PlatformID, a.NodeID, a.Comment, a.IsActive))
}

// UpdateAsset 更新资产所有字段，同时刷新 updated_at，返回更新后的记录。
func (s *Store) UpdateAsset(a *domain.Asset) error {
	q := s.query(`UPDATE assets SET name = ?, address = ?, platform_id = ?, node_id = ?, comment = ?,
		is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Address, a.PlatformID, a.NodeID, a.Comment, a.IsActive, a.ID))
}

// GetAsset 按 ID 查询资产记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetAsset(id int64) (domain.Asset, error) {
	var a domain.Asset
	err := s.db.Get(&a, s.query(`SELECT * FROM assets WHERE id = ?`), id)
	return a, notFound(err)
}

// GetAssetProtocolPort 通过资产关联的平台协议配置，查询指定协议对应的端口号
// 查询逻辑：JOIN platform_protocols 表，根据 asset_id 和 protocol name 获取端口
func (s *Store) GetAssetProtocolPort(assetID int64, protocol string) (int, error) {
	var port int
	names := protocolAliases(protocol)
	placeholders := make([]string, len(names))
	args := make([]any, 0, len(names)+1)
	args = append(args, assetID)
	for i, name := range names {
		placeholders[i] = "?"
		args = append(args, name)
	}
	err := s.db.Get(&port, s.query(`SELECT pp.port
		FROM assets a
		JOIN platform_protocols pp ON pp.platform_id = a.platform_id
		WHERE a.id = ? AND pp.name IN (`+strings.Join(placeholders, ",")+`)
		LIMIT 1`), args...)
	return port, notFound(err)
}

func protocolAliases(protocol string) []string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case "postgres", "postgresql":
		return []string{"postgres", "postgresql"}
	default:
		return []string{protocol}
	}
}

// ListAssets 返回所有资产列表（含 JOIN 平台表获取平台名称和类型），按资产 ID 升序排列。
func (s *Store) ListAssets() ([]domain.AssetWithPlatform, error) {
	var assets []domain.AssetWithPlatform
	err := s.db.Select(&assets, `SELECT a.*, p.name AS platform_name, p.type AS platform_type
		FROM assets a JOIN platforms p ON p.id = a.platform_id ORDER BY a.id`)
	return assets, err
}

// DeleteAsset 按 ID 删除资产记录。
func (s *Store) DeleteAsset(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM assets WHERE id = ?`), id)
	return err
}

// ListNodes 返回所有节点列表（资产树节点），按 ID 升序排列。
func (s *Store) ListNodes() ([]domain.Node, error) {
	var nodes []domain.Node
	err := s.db.Select(&nodes, `SELECT * FROM nodes ORDER BY id`)
	return nodes, err
}

// CreateAccount 为资产创建关联账号，INSERT 后通过 RETURNING * 返回完整记录。
func (s *Store) CreateAccount(a *domain.Account) error {
	q := s.query(`INSERT INTO accounts (asset_id, name, username, secret, secret_type, ssh_key_type, passphrase,
		su_enabled, su_method, su_account_id, db_name, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(a, q, a.AssetID, a.Name, a.Username, a.Secret, a.SecretType, a.SSHKeyType, a.Passphrase,
		a.SUEnabled, a.SUMethod, a.SUAccountID, a.DBName, a.IsActive))
}

// UpdateAccount 更新账号所有字段（含 SU 切换和数据库名），同时刷新 updated_at，返回更新后的记录。
func (s *Store) UpdateAccount(a *domain.Account) error {
	q := s.query(`UPDATE accounts SET name = ?, username = ?, secret = ?, secret_type = ?, ssh_key_type = ?,
		passphrase = ?, su_enabled = ?, su_method = ?, su_account_id = ?, db_name = ?, is_active = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ? AND asset_id = ? RETURNING *`)
	return notFound(s.db.Get(a, q, a.Name, a.Username, a.Secret, a.SecretType, a.SSHKeyType, a.Passphrase,
		a.SUEnabled, a.SUMethod, a.SUAccountID, a.DBName, a.IsActive, a.ID, a.AssetID))
}

// GetAccount 按 ID 查询账号记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetAccount(id int64) (domain.Account, error) {
	var a domain.Account
	err := s.db.Get(&a, s.query(`SELECT * FROM accounts WHERE id = ?`), id)
	return a, notFound(err)
}

// GetAssetAccount 按账号 ID 和资产 ID 联合查询，确保账号属于指定资产，未找到时返回 domain.ErrNotFound。
func (s *Store) GetAssetAccount(assetID, accountID int64) (domain.Account, error) {
	var a domain.Account
	err := s.db.Get(&a, s.query(`SELECT * FROM accounts WHERE id = ? AND asset_id = ?`), accountID, assetID)
	return a, notFound(err)
}

// ListAccounts 返回指定资产关联的所有账号列表，按 ID 升序排列。
func (s *Store) ListAccounts(assetID int64) ([]domain.Account, error) {
	var accounts []domain.Account
	err := s.db.Select(&accounts, s.query(`SELECT * FROM accounts WHERE asset_id = ? ORDER BY id`), assetID)
	return accounts, err
}

// DeleteAccount 按资产 ID 和账号 ID 联合删除账号记录。
func (s *Store) DeleteAccount(assetID, accountID int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM accounts WHERE id = ? AND asset_id = ?`), accountID, assetID)
	return err
}

// PermissionLinks 定义资产权限关联的实体 ID 集合：用户、用户组、资产、节点、账号。
type PermissionLinks struct {
	UserIDs    []int64 `json:"user_ids"`
	GroupIDs   []int64 `json:"group_ids"`
	AssetIDs   []int64 `json:"asset_ids"`
	NodeIDs    []int64 `json:"node_ids"`
	AccountIDs []int64 `json:"account_ids"`
}

// CreatePermission 在事务中创建资产权限策略及其关联实体。
// 先 INSERT 权限主记录，再调用 insertPermissionLinks 写入关联表。
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

// UpdatePermission 在事务中更新资产权限策略及其关联实体。
// 先 UPDATE 权限主记录，再清空并重新写入所有关联表。
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

// insertPermissionLinks 将权限关联的各类实体 ID 批量写入对应的关联表。
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

// GetPermission 按 ID 查询资产权限及其关联的所有实体 ID 集合。
func (s *Store) GetPermission(id int64) (domain.AssetPermission, PermissionLinks, error) {
	var p domain.AssetPermission
	if err := s.db.Get(&p, s.query(`SELECT * FROM asset_permissions WHERE id = ?`), id); err != nil {
		return p, PermissionLinks{}, notFound(err)
	}
	links, err := s.PermissionLinks(id)
	return p, links, err
}

// ListPermissions 返回所有资产权限列表，按 ID 升序排列。
func (s *Store) ListPermissions() ([]domain.AssetPermission, error) {
	var permissions []domain.AssetPermission
	err := s.db.Select(&permissions, `SELECT * FROM asset_permissions ORDER BY id`)
	return permissions, err
}

// PermissionLinks 查询指定权限 ID 关联的所有实体 ID（用户、用户组、资产、节点、账号）。
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

// DeletePermission 按 ID 删除资产权限记录。
func (s *Store) DeletePermission(id int64) error {
	_, err := s.db.Exec(s.query(`DELETE FROM asset_permissions WHERE id = ?`), id)
	return err
}

// HasAssetPermission 检查用户是否对指定资产拥有指定操作的权限。
// 通过多层 JOIN 查询资产权限表：验证用户关联、资产关联、权限生效时间、actions 模糊匹配及账号级过滤。
func (s *Store) HasAssetPermission(userID, assetID, accountID int64, action string) (bool, error) {
	var n int
	q := s.query(`WITH RECURSIVE asset_node_ids(id, parent_id) AS (
			SELECT n.id, n.parent_id
			FROM nodes n
			JOIN assets a ON a.node_id = n.id
			WHERE a.id = ?
			UNION
			SELECT n.id, n.parent_id
			FROM nodes n
			JOIN asset_nodes an ON an.node_id = n.id
			WHERE an.asset_id = ?
			UNION
			SELECT parent.id, parent.parent_id
			FROM nodes parent
			JOIN asset_node_ids child ON child.parent_id = parent.id
		)
		SELECT COUNT(1)
		FROM asset_permissions p
		WHERE p.is_active = ?
		  AND (p.date_start IS NULL OR p.date_start <= CURRENT_TIMESTAMP)
		  AND (p.date_expired IS NULL OR p.date_expired > CURRENT_TIMESTAMP)
		  AND (',' || p.actions || ',') LIKE ?
		  AND (
		    EXISTS (SELECT 1 FROM perm_users pu WHERE pu.permission_id = p.id AND pu.user_id = ?)
		    OR EXISTS (
		      SELECT 1
		      FROM perm_user_groups pug
		      JOIN group_users gu ON gu.group_id = pug.group_id
		      WHERE pug.permission_id = p.id AND gu.user_id = ?
		    )
		  )
		  AND (
		    EXISTS (SELECT 1 FROM perm_assets pa WHERE pa.permission_id = p.id AND pa.asset_id = ?)
		    OR EXISTS (
		      SELECT 1
		      FROM perm_nodes pn
		      JOIN asset_node_ids ani ON ani.id = pn.node_id
		      WHERE pn.permission_id = p.id
		    )
		  )
		  AND (
		    EXISTS (SELECT 1 FROM perm_accounts pac WHERE pac.permission_id = p.id AND pac.account_id = ?)
		    OR NOT EXISTS (SELECT 1 FROM perm_accounts pac2 WHERE pac2.permission_id = p.id)
		  )`)
	err := s.db.Get(&n, q, assetID, assetID, true, "%,"+action+",%", userID, userID, assetID, accountID)
	return n > 0, err
}

// CreateConnectionToken 创建连接令牌，INSERT 后通过 RETURNING * 返回完整记录。
func (s *Store) CreateConnectionToken(t *domain.ConnectionToken) error {
	q := s.query(`INSERT INTO connection_tokens (value, user_id, asset_id, account_id, protocol, connect_method,
		is_reusable, connect_options, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(t, q, t.Value, t.UserID, t.AssetID, t.AccountID, t.Protocol, t.ConnectMethod,
		t.IsReusable, t.ConnectOptions, t.ExpiresAt))
}

// GetConnectionToken 按令牌值查询连接令牌记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetConnectionToken(value string) (domain.ConnectionToken, error) {
	var t domain.ConnectionToken
	err := s.db.Get(&t, s.query(`SELECT * FROM connection_tokens WHERE value = ?`), value)
	return t, notFound(err)
}

// ConsumeConnectionToken 原子领取一次性连接令牌。只有未过期且未使用的非复用 token 会被标记 used_at 并返回。
func (s *Store) ConsumeConnectionToken(value string) (domain.ConnectionToken, error) {
	var t domain.ConnectionToken
	q := s.query(`UPDATE connection_tokens SET used_at = CURRENT_TIMESTAMP
		WHERE value = ? AND is_reusable = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
		RETURNING *`)
	err := s.db.Get(&t, q, value, false)
	return t, notFound(err)
}

// CreateSession 创建会话记录，INSERT 后通过 RETURNING * 返回完整记录。
func (s *Store) CreateSession(sess *domain.Session) error {
	q := s.query(`INSERT INTO sessions (user_id, asset_id, account_id, protocol, type, login_from, remote_addr,
		recording_path, is_finished)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
	return notFound(s.db.Get(sess, q, sess.UserID, sess.AssetID, sess.AccountID, sess.Protocol, sess.Type,
		sess.LoginFrom, sess.RemoteAddr, sess.RecordingPath, sess.IsFinished))
}

// UpdateSession 更新会话状态（结束时间、录制路径、是否完成），同时刷新 updated_at，返回更新后的记录。
func (s *Store) UpdateSession(sess *domain.Session) error {
	q := s.query(`UPDATE sessions SET is_finished = ?, date_end = ?, recording_path = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? RETURNING *`)
	return notFound(s.db.Get(sess, q, sess.IsFinished, sess.DateEnd, sess.RecordingPath, sess.ID))
}

// GetSession 按 ID 查询会话记录，未找到时返回 domain.ErrNotFound。
func (s *Store) GetSession(id int64) (domain.Session, error) {
	var sess domain.Session
	err := s.db.Get(&sess, s.query(`SELECT * FROM sessions WHERE id = ?`), id)
	return sess, notFound(err)
}

// ListSessions 返回所有会话列表，按 ID 降序排列（最新的在前）。
func (s *Store) ListSessions() ([]domain.Session, error) {
	var sessions []domain.Session
	err := s.db.Select(&sessions, `SELECT * FROM sessions ORDER BY id DESC`)
	return sessions, err
}

// DashboardSummary 返回仪表盘统计和最近会话，避免控制台周期性请求扫描全量会话数据。
func (s *Store) DashboardSummary(todayStart time.Time, recentLimit int) (DashboardSummary, error) {
	if recentLimit <= 0 {
		recentLimit = 10
	}
	var out DashboardSummary
	if err := s.db.Get(&out.TotalAssets, `SELECT COUNT(1) FROM assets`); err != nil {
		return out, err
	}
	if err := s.db.Get(&out.ActiveSessions, `SELECT COUNT(1) FROM sessions WHERE is_finished = false`); err != nil {
		return out, err
	}
	if err := s.db.Get(&out.TodaySessions, s.query(`SELECT COUNT(1) FROM sessions WHERE date_start >= ?`), todayStart); err != nil {
		return out, err
	}
	if err := s.db.Get(&out.ActiveUsers, `SELECT COUNT(DISTINCT user_id) FROM sessions WHERE is_finished = false`); err != nil {
		return out, err
	}
	q := s.query(`SELECT s.*,
			u.username AS username,
			u.name AS user_name,
			a.name AS asset_name,
			COALESCE(NULLIF(ac.name, ''), ac.username) AS account_name
		FROM sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN assets a ON a.id = s.asset_id
		LEFT JOIN accounts ac ON ac.id = s.account_id
		ORDER BY s.id DESC
		LIMIT ?`)
	if err := s.db.Select(&out.RecentSessions, q, recentLimit); err != nil {
		return out, err
	}
	if out.RecentSessions == nil {
		out.RecentSessions = []domain.SessionSummary{}
	}
	return out, nil
}

// UpsertSetting 创建或更新系统设置项。
// PostgreSQL 使用 ON CONFLICT ... DO UPDATE 语法，SQLite 使用 ON CONFLICT(key) DO UPDATE 语法。
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

// GetSetting 按 key 查询系统设置项，未找到时返回 domain.ErrNotFound。
func (s *Store) GetSetting(key string) (domain.Setting, error) {
	var setting domain.Setting
	err := s.db.Get(&setting, s.query(`SELECT * FROM settings WHERE key = ?`), key)
	return setting, notFound(err)
}

// ListSettings 返回所有系统设置列表，按分类和 key 升序排列。
func (s *Store) ListSettings() ([]domain.Setting, error) {
	var settings []domain.Setting
	err := s.db.Select(&settings, `SELECT * FROM settings ORDER BY category, key`)
	return settings, err
}

// ListAuditLogs 返回符合条件的审计日志列表和总数，按 ID 降序排列（最新的在前）。
func (s *Store) ListAuditLogs(filter AuditLogFilter) ([]domain.AuditLog, int, error) {
	var logs []domain.AuditLog
	where, args := auditLogWhere(filter)
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	var total int
	countQuery := s.query(`SELECT COUNT(*) FROM audit_logs ` + where)
	if err := s.db.Get(&total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	listArgs := append([]any{}, args...)
	listArgs = append(listArgs, limit, offset)
	listQuery := s.query(`SELECT * FROM audit_logs ` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`)
	if err := s.db.Select(&logs, listQuery, listArgs...); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// ListSessionCommandLogs 返回指定会话关联的命令/SQL审计日志。
func (s *Store) ListSessionCommandLogs(sessionID int64) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog
	if err := s.db.Select(&logs, `SELECT * FROM audit_logs WHERE action IN ('db.query', 'ssh.command') ORDER BY id DESC`); err != nil {
		return nil, err
	}
	filtered := logs[:0]
	for _, log := range logs {
		if auditLogSessionID(log.Detail) == sessionID {
			filtered = append(filtered, log)
		}
	}
	return filtered, nil
}

func auditLogWhere(filter AuditLogFilter) (string, []any) {
	conditions := []string{"1 = 1"}
	args := []any{}
	if filter.UserID > 0 {
		conditions = append(conditions, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if action := strings.TrimSpace(filter.Action); action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, action)
	}
	if filter.DateFrom != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filter.DateFrom)
	}
	if filter.DateTo != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filter.DateTo)
	}
	if search := strings.ToLower(strings.TrimSpace(filter.Search)); search != "" {
		conditions = append(conditions, `LOWER(
			action || ' ' || resource || ' ' || remote_addr || ' ' || CAST(detail AS TEXT) || ' ' ||
			COALESCE(CAST(user_id AS TEXT), '')
		) LIKE ?`)
		args = append(args, "%"+search+"%")
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func auditLogSessionID(detail string) int64 {
	var payload struct {
		SessionID int64 `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(detail), &payload); err != nil {
		return 0
	}
	return payload.SessionID
}

// Audit 写入一条审计日志记录。
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

// withTx 在数据库事务中执行回调函数，自动处理 begin/commit/rollback。
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

// NormalizeActions 将操作列表归一化为逗号分隔的字符串。
// 去重并去除空值，若结果为空则返回默认值 "connect"。
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

// NowPtr 返回当前 UTC 时间的指针，方便设置数据库记录的时间字段。
func NowPtr() *time.Time {
	now := time.Now().UTC()
	return &now
}
