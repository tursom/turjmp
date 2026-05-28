-- +goose Up
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE user_groups (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    org_id BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE group_users (
    group_id BIGINT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE platforms (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE platform_protocols (
    id BIGSERIAL PRIMARY KEY,
    platform_id BIGINT NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    port INTEGER NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(platform_id, name)
);

CREATE TABLE nodes (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id BIGINT NULL REFERENCES nodes(id) ON DELETE SET NULL,
    org_id BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE assets (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    platform_id BIGINT NOT NULL REFERENCES platforms(id),
    node_id BIGINT NULL REFERENCES nodes(id) ON DELETE SET NULL,
    comment TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE asset_nodes (
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    node_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, node_id)
);

CREATE TABLE accounts (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    secret TEXT NOT NULL DEFAULT '',
    secret_type TEXT NOT NULL DEFAULT 'password',
    ssh_key_type TEXT NOT NULL DEFAULT '',
    passphrase TEXT NOT NULL DEFAULT '',
    su_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    su_method TEXT NOT NULL DEFAULT '',
    su_account_id BIGINT NULL REFERENCES accounts(id) ON DELETE SET NULL,
    db_name TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE gateways (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    account_id BIGINT NULL REFERENCES accounts(id) ON DELETE SET NULL,
    protocol TEXT NOT NULL DEFAULT 'ssh',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE asset_gateways (
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    gateway_id BIGINT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, gateway_id)
);

CREATE TABLE host_keys (
    id BIGSERIAL PRIMARY KEY,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE asset_permissions (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    actions TEXT NOT NULL DEFAULT 'connect',
    date_start TIMESTAMPTZ NULL,
    date_expired TIMESTAMPTZ NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE perm_users (
    permission_id BIGINT NOT NULL REFERENCES asset_permissions(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, user_id)
);

CREATE TABLE perm_user_groups (
    permission_id BIGINT NOT NULL REFERENCES asset_permissions(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, group_id)
);

CREATE TABLE perm_assets (
    permission_id BIGINT NOT NULL REFERENCES asset_permissions(id) ON DELETE CASCADE,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, asset_id)
);

CREATE TABLE perm_nodes (
    permission_id BIGINT NOT NULL REFERENCES asset_permissions(id) ON DELETE CASCADE,
    node_id BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, node_id)
);

CREATE TABLE perm_accounts (
    permission_id BIGINT NOT NULL REFERENCES asset_permissions(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, account_id)
);

CREATE TABLE connection_tokens (
    id BIGSERIAL PRIMARY KEY,
    value TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    connect_method TEXT NOT NULL,
    is_reusable BOOLEAN NOT NULL DEFAULT FALSE,
    connect_options JSONB NOT NULL DEFAULT '{}'::jsonb,
    used_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    asset_id BIGINT NOT NULL REFERENCES assets(id),
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    protocol TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'normal',
    login_from TEXT NOT NULL DEFAULT 'WT',
    remote_addr TEXT NOT NULL DEFAULT '',
    recording_path TEXT NOT NULL DEFAULT '',
    is_finished BOOLEAN NOT NULL DEFAULT FALSE,
    date_start TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    date_end TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE session_recordings (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    storage TEXT NOT NULL DEFAULT 'local',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE command_filter_acls (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'reject',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_acls (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    rule TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'allow',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    remote_addr TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE casbin_rules (
    id BIGSERIAL PRIMARY KEY,
    ptype TEXT NOT NULL,
    v0 TEXT NOT NULL DEFAULT '',
    v1 TEXT NOT NULL DEFAULT '',
    v2 TEXT NOT NULL DEFAULT '',
    v3 TEXT NOT NULL DEFAULT '',
    v4 TEXT NOT NULL DEFAULT '',
    v5 TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_casbin_rules_unique ON casbin_rules(ptype, v0, v1, v2, v3, v4, v5);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    label TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    input_type TEXT NOT NULL DEFAULT 'text',
    options TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS casbin_rules;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS login_acls;
DROP TABLE IF EXISTS command_filter_acls;
DROP TABLE IF EXISTS session_recordings;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS connection_tokens;
DROP TABLE IF EXISTS perm_accounts;
DROP TABLE IF EXISTS perm_nodes;
DROP TABLE IF EXISTS perm_assets;
DROP TABLE IF EXISTS perm_user_groups;
DROP TABLE IF EXISTS perm_users;
DROP TABLE IF EXISTS asset_permissions;
DROP TABLE IF EXISTS host_keys;
DROP TABLE IF EXISTS asset_gateways;
DROP TABLE IF EXISTS gateways;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS asset_nodes;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS platform_protocols;
DROP TABLE IF EXISTS platforms;
DROP TABLE IF EXISTS group_users;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

