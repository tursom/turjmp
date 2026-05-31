// Auth
export interface LoginRequest {
  username: string
  password: string
  mfa_code?: string
}

export interface LoginResult {
  require_mfa?: boolean
  require_mfa_setup?: boolean
  access_token?: string
  access_token_expires_at?: string
  refresh_token?: string
  refresh_token_expires_at?: string
  user?: User
  roles?: string[]
}

export type AccessMap = Record<string, boolean>

export interface RefreshRequest {
  refresh_token: string
}

export interface MFAVerifyRequest {
  code: string
}

// Domain entities
export interface User {
  id: number
  username: string
  name: string
  email: string
  mfa_enabled: boolean
  is_active: boolean
  last_login_at?: string
  created_at: string
  updated_at: string
}

export interface CreateUserInput {
  username: string
  name: string
  email: string
  password: string
  is_active?: boolean
  role_ids?: number[]
}

export interface UpdateUserInput {
  username?: string
  name?: string
  email?: string
  password?: string
  is_active?: boolean
  role_ids?: number[]
}

export interface Role {
  id: number
  name: string
  description: string
  created_at: string
  updated_at: string
}

export interface UserGroup {
  id: number
  name: string
  org_id: number
  created_at: string
  updated_at: string
}

export interface CreateRoleInput {
  name: string
  description: string
}

export interface PermissionRule {
  path: string
  method: string
}

export interface SetPermissionsInput {
  permissions: PermissionRule[]
}

export interface Platform {
  id: number
  name: string
  type: string
  description: string
  created_at: string
}

export interface PlatformProtocol {
  id: number
  platform_id: number
  name: string
  port: number
  settings: string
  created_at: string
}

export interface Asset {
  id: number
  name: string
  address: string
  platform_id: number
  node_id?: number
  comment: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface AssetWithPlatform extends Asset {
  platform_name: string
  platform_type: string
}

export interface CreateAssetInput {
  name: string
  address: string
  platform_id: number
  node_id?: number
  comment?: string
  is_active?: boolean
}

export interface AssetListResponse {
  items: AssetWithPlatform[]
  total: number
  page: number
  per_page: number
}

export interface CreatePlatformInput {
  name: string
  type: string
  description?: string
  protocol?: string
  port?: number
}

export interface Node {
  id: number
  name: string
  parent_id?: number
  org_id: number
  created_at: string
  updated_at: string
}

export interface AssetTreeData {
  nodes: Node[]
  assets: AssetWithPlatform[]
}

export interface Account {
  id: number
  asset_id: number
  name: string
  username: string
  secret_type: 'password' | 'ssh_key' | 'token'
  secret: string
  ssh_key_type?: string
  passphrase: string
  su_enabled: boolean
  su_method?: string
  su_account_id?: number
  db_name?: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface AccountInput {
  name: string
  username: string
  secret: string
  secret_type: 'password' | 'ssh_key' | 'token'
  ssh_key_type?: string
  passphrase?: string
  su_enabled?: boolean
  su_method?: string
  su_account_id?: number
  db_name?: string
  is_active?: boolean
}

export interface AssetPermission {
  id: number
  name: string
  actions: string
  date_start?: string
  date_expired?: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface PermissionInput {
  name: string
  actions: string[]
  date_start?: string
  date_expired?: string
  is_active?: boolean
  user_ids?: number[]
  group_ids?: number[]
  asset_ids?: number[]
  node_ids?: number[]
  account_ids?: number[]
}

export interface Session {
  id: number
  user_id: number
  asset_id: number
  account_id: number
  protocol: string
  type: string
  login_from: string
  remote_addr: string
  recording_path?: string
  is_finished: boolean
  date_start: string
  date_end?: string
  created_at: string
  updated_at: string
}

export interface DashboardSummary {
  total_assets: number
  active_sessions: number
  today_sessions: number
  active_users: number
  recent_sessions: Session[]
  generated_at: string
}

export interface StreamTokenResult {
  token: string
  expires_at: string
  expires_in: number
}

export interface SessionRecording {
  recording_path: string
  url: string
  download_url: string
  available: boolean
}

export interface Setting {
  key: string
  value: string
  category: string
  label: string
  description: string
  input_type: 'text' | 'number' | 'select' | 'toggle' | 'secret'
  options?: string
  updated_at: string
}

export interface SettingsByCategory {
  [category: string]: Setting[]
}

export interface AuditLog {
  id: number
  user_id?: number
  action: string
  resource: string
  remote_addr: string
  detail: string
  created_at: string
}

export interface AuditLogListResponse {
  items: AuditLog[]
  total: number
  page: number
  per_page: number
}

export interface ConnectionTokenResult {
  token: string
  expires_at: string
  expires_in: number
}

export interface SDKURLResult {
  token: string
  expires_at: string
  expires_in: number
  protocol: string
  connect_method: string
  host: string
  port: number
  command: string
  filename: string
  mime_type: string
  content?: string
  web_url?: string
}

export interface SSHFingerprint {
  algorithm: string
  fingerprint: string
  public_key: string
}

export interface IssueTokenInput {
  asset_id: number
  account_id: number
  protocol?: string
  connect_method?: string
  is_reusable?: boolean
  connect_options?: string
}

export interface SDKURLInput {
  asset_id: number
  account_id: number
  protocol?: string
  connect_method?: string
  proxy_host?: string
  format?: string
}

export interface UserDetail {
  user: User
  roles: Role[]
}

export interface RoleDetail {
  role: Role
  permissions: string[][]
}

export interface PermissionLinks {
  user_ids?: number[]
  group_ids?: number[]
  asset_ids?: number[]
  node_ids?: number[]
  account_ids?: number[]
}

export interface PermissionDetail {
  permission: AssetPermission
  links: PermissionLinks
}

// API response envelope
export interface ApiResponse<T> {
  data: T
}

export interface ApiError {
  error: {
    code: string
    message: string
  }
}
