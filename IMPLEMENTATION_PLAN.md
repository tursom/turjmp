# Turjmp — Bastion Host (Jump Server) Implementation Plan

> JumpServer 同类功能 | 前后分离 | Go 后端 | Vue 3 前端 | Web + 原生客户端双通道

---

## 目录

- [总体架构](#总体架构)
- [技术选型总览](#技术选型总览)
- [数据模型设计](#数据模型设计)
- [后端实现计划](#后端实现计划)
  - [Phase B1: 基础设施](#phase-b1-基础设施)
  - [Phase B2: SSH 代理](#phase-b2-ssh-代理)
  - [Phase B3: 数据库代理 (MySQL / PostgreSQL)](#phase-b3-数据库代理-mysql--postgresql)
  - [Phase B4: RDP 代理](#phase-b4-rdp-代理)
  - [Phase B5: 原生客户端透传](#phase-b5-原生客户端透传)
- [前端实现计划](#前端实现计划)
  - [Phase F1: 管理控制台](#phase-f1-管理控制台)
  - [Phase F2: Web 终端访问](#phase-f2-web-终端访问)
  - [Phase F3: 会话回放 & 原生客户端接入](#phase-f3-会话回放--原生客户端接入)
- [API 设计纲要](#api-设计纲要)
- [部署架构](#部署架构)

---

## 总体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           前端 (Vue 3 + TypeScript)                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │  管理控制台 (Lina) │  │  Web 终端 (Luna)  │  │ 会话回放 & 审计       │  │
│  │  用户/资产/权限    │  │  xterm.js + WS   │  │ asciinema-player     │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────────┬───────────┘  │
│           │                     │                        │              │
│           │        HTTP/WS      │        HTTP/WS         │              │
└───────────┼─────────────────────┼────────────────────────┼──────────────┘
            │                     │                        │
════════════│═════════════════════│════════════════════════│═══════════════
            │           Nginx / Traefik (路由 + TLS)       │
════════════│═════════════════════│════════════════════════│═══════════════
            │                     │                        │
┌───────────┼─────────────────────┼────────────────────────┼──────────────┐
│           ▼                     ▼                        ▼              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    API Server (Gin)                               │  │
│  │  用户 · 资产 · 权限 · RBAC · 会话管理 · Connection Token 签发     │  │
│  └──────────────────────────────┬───────────────────────────────────┘  │
│                                 │                                      │
│  ┌──────────────────────────────┼───────────────────────────────────┐  │
│  │                    接入层 — 协议代理                               │  │
│  │                                                                   │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │  │
│  │  │ SSH Proxy    │ │ DB Proxy     │  │ RDP Proxy    │              │  │
│  │  │ (Port 2222)  │ │ (3307/5437)  │  │ (3389/guacd) │              │  │
│  │  │ gliderlabs   │ │ go-mysql +   │  │ wwt/guac +   │              │  │
│  │  │ /ssh         │ │ pgproto3     │  │ guacd sidecar│              │  │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘              │  │
│  │         │                │                │                       │  │
│  │         │ Token 验证     │ Token 验证      │ Token 验证           │  │
│  │         ▼                ▼                ▼                       │  │
│  │  ┌──────────────────────────────────────────────────────────┐    │  │
│  │  │              Connection Token Engine                      │    │  │
│  │  │  验证 → 查资产 → 查账号密码 → 鉴权 ACL → 建立连接         │    │  │
│  │  └──────────────────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    存储层                                          │  │
│  │  PostgreSQL (主库)  ·  Redis (缓存/WS) ·  S3/MinIO (录像)  ·      │  │
│  │  guacd (RDP 协议引擎，C 守护进程)                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘

                     Web 通道                               原生客户端通道
      ┌────────────────────────────────┐    ┌──────────────────────────────────┐
      │  Luna → WS → Proxy → 目标资产   │    │  ssh client → SSH Proxy → 目标    │
      │  (浏览器内终端)                 │    │  Navicat → Magnus → MySQL 目标     │
      │                                │    │  mstsc → Razor → RDP 目标          │
      └────────────────────────────────┘    └──────────────────────────────────┘
```

---

## 技术选型总览

| 组件 | 库 | 版本 | 理由 |
|---|---|---|---|
| **HTTP 框架** | `gin-gonic/gin` | v1.10+ | RouterGroup 映射清晰，JumpServer KoKo 同款 |
| **WebSocket** | `coder/websocket` | latest | 替代已归档的 gorilla，context 友好，零依赖 |
| **数据库访问 (管理)** | `jmoiron/sqlx` | v1.3+ | database/sql 封装，结构体扫描，命名参数，手写 SQL |
| **SQLite 驱动** | `modernc.org/sqlite` | latest | 纯 Go，无 CGO，轻量化单文件部署 |
| **PostgreSQL 驱动** | `jackc/pgx/v5` | v5.7+ | 生产环境主库 + 录像高吞吐写入 (COPY 协议) |
| **数据库迁移** | `pressly/goose/v3` | latest | SQL + Go 混合迁移，embed.FS 支持，同时支持 SQLite 和 PG |
| **配置** | `knadh/koanf/v2` | latest | 4x 更小二进制，Provider/Parser 分离架构 |
| **JWT** | `golang-jwt/jwt/v5` | latest | RS256 非对称签名，代理层无需共享密钥 |
| **TOTP** | `pquerna/otp` | latest | RFC 6238 |
| **RBAC** | `apache/casbin` | v2 | 成熟 ACL/RBAC/ABAC，RESTful 路径匹配 |
| **SSH 服务端** | `gliderlabs/ssh` | v0.3.8 | 标准 Go SSH server |
| **SSH 客户端** | `golang.org/x/crypto/ssh` | v0.52 | 连接到目标资产 |
| **MySQL 代理** | `go-mysql-org/go-mysql` | v1.15 | Fake server + Handler 接口 |
| **PG 代理** | `jackc/pgx/v5/pgproto3` | — | PG wire protocol 编解码 |
| **RDP 代理** | `wwt/guac` + guacd | v1.3.2 | Guacamole 协议 Go 客户端 |
| **PTY** | `creack/pty` | v1.1+ | PTY 分配与调整大小 |
| **会话录制** | Asciicast v2 JSON | — | 可压缩，可流式，可 Web 回放 |
| **测试** | `testcontainers-go` | v0.38+ | 每测试真实 PG/MySQL/SSH 容器 |
| **日志** | `go.uber.org/zap` | v1.27+ | 高吞吐结构化日志 |
| **可观测性** | OpenTelemetry + Prometheus | — | 分布式追踪 + 指标 |
| **前端框架** | Vue 3 + TypeScript + Vite | — | Composition API + Pinia + Vue Router |
| **终端** | xterm.js + @xterm/addon-fit | v5+ | 浏览器内终端模拟器 |
| **RDP Web** | Guacamole JS client | — | 浏览器内 RDP 渲染 |
| **会话回放** | asciinema-player | latest | Cast 文件 Web 播放器 |

---

## 数据模型设计

### 核心实体关系

```
Organization (多租户预留)
  │ 1:N
  ▼
User ─── N:M ─── Role ─── 1:N ─── Permission (Casbin Policy)
  │
  │ N:M (via AssetPermission)
  ▼
Asset ─── N:1 ─── Platform (Linux/Windows/MySQL/PG...)
  │                  │
  │ 1:N              │ 1:N
  ▼                  ▼
Protocol             PlatformProtocol (模板: 端口/设置)
  (name=ssh,rdp,     │
   port=22/3389)     ▼
                   AssetProtocol (实例: 继承+覆盖)
  │
  │ 1:N
  ▼
Account (username + secret + su_from)
  │
  │ 组成
  ▼
AssetPermission ─── N:M ─── User / UserGroup
  └── N:M ─── Asset / Node
  └── N:M ─── Account
  └── actions (connect/upload/download)
  └── date_start / date_expired

ConnectionToken
  value (UUID)     user_id       asset_id
  account_id       protocol      connect_method (web_cli/web_gui/ssh_client)
  is_reusable      date_expired   connect_options (JSON)

Session
  user_id    asset_id    account_id    protocol
  type (normal/tunnel/sftp/db)       login_from (WT/ST/DT)
  remote_addr    date_start    date_end    is_finished
  recording_path (cast file / S3 URL)
```

### 数据模型补充字段

> **注意**: 以下实体关系中未画出的补充表:

| 表 | 关键字段 | 用途 |
|---|---|---|
| `nodes` | id, name, parent_id, org_id | 资产树节点（树形结构 via parent_id 自引用） |
| `asset_nodes` | asset_id, node_id | 资产-节点多对多关联 |
| `user_groups` | id, name, org_id | 用户组 |
| `group_users` | group_id, user_id | 用户-用户组关联 |
| `gateways` | id, name, address, port, account_id, protocol | SSH 网关/跳板（用于资产间接访问） |
| `asset_gateways` | asset_id, gateway_id | 资产-网关关联 |
| `host_keys` | id, algorithm, fingerprint, private_key, public_key, created_at | SSH 主机密钥管理 |

**Account 表补充字段**:

| 字段 | 类型 | 用途 |
|---|---|---|
| `secret_type` | enum(password,ssh_key,token) | 凭据类型 |
| `ssh_key_type` | varchar(20) | SSH 密钥算法 (rsa/ed25519/ecdsa) |
| `passphrase` | text (encrypted) | SSH 密钥口令（可选） |
| `su_enabled` | bool | 是否启用 su 切换 |
| `su_method` | enum(su,sudo,enable) | 特权提升方式 |
| `su_account_id` | FK → accounts | su 目标账号 |
| `db_name` | varchar(128) | 数据库连接的目标数据库名（MySQL/PG） |

### 数据库表清单

```
users                — 用户
roles                — 角色
user_roles           — 用户-角色关联
user_groups          — 用户组
group_users          — 用户组-用户关联
platforms            — 平台模板 (linux, windows, mysql, postgres, ...)
platform_protocols   — 平台协议模板
assets               — 资产
asset_protocols      — 资产协议实例
nodes                — 资产树节点
asset_nodes          — 资产-节点关联
accounts             — 账号 (含加密密码/密钥)
gateways             — SSH 网关（跳板）
asset_gateways       — 资产-网关关联
host_keys            — SSH 主机密钥
asset_permissions    — 资产授权
perm_users           — 授权-用户关联
perm_user_groups     — 授权-用户组关联
perm_assets          — 授权-资产关联
connection_tokens    — 连接令牌
sessions             — 会话记录
session_recordings   — 会话录像元数据
command_filter_acls  — 命令过滤 ACL
login_acls           — 登录 ACL
audit_logs           — 审计日志 (SQL 查询等)
casbin_rules         — Casbin RBAC 策略
settings             — 系统配置 (前端可配，运行时动态生效)
```

---

## 后端实现计划

### 项目结构

```
turjmp/
├── cmd/
│   └── turjmp/main.go              # 单二进制多角色入口 (--api / --ssh-proxy / --db-proxy / --rdp-proxy / --migrate)
│
├── internal/
│   ├── domain/                     # 核心实体 + 接口 (零依赖)
│   │   ├── user.go
│   │   ├── asset.go
│   │   ├── platform.go
│   │   ├── account.go
│   │   ├── permission.go
│   │   ├── session.go
│   │   └── errors.go
│   │
│   ├── config/                     # koanf 配置
│   │   └── config.go
│   │
│   ├── api/                        # REST API 层
│   │   ├── router.go
│   │   ├── middleware/
│   │   │   ├── auth.go             # JWT 中间件
│   │   │   ├── rbac.go             # Casbin 中间件
│   │   │   └── audit.go
│   │   ├── handler/
│   │   │   ├── auth_handler.go     # 登录/登出/MFA
│   │   │   ├── user_handler.go
│   │   │   ├── asset_handler.go
│   │   │   ├── permission_handler.go
│   │   │   ├── session_handler.go
│   │   │   └── token_handler.go    # Connection Token API
│   │   └── dto/                    # 请求/响应 DTO
│   │
│   ├── service/                    # 业务逻辑
│   │   ├── auth_service.go
│   │   ├── user_service.go
│   │   ├── asset_service.go
│   │   ├── permission_service.go
│   │   ├── session_service.go
│   │   └── token_service.go
│   │
│   ├── repository/                 # 数据访问 (sqlx + pgx)
│   │   ├── user_repo.go
│   │   ├── asset_repo.go
│   │   ├── session_repo.go
│   │   └── recording_repo.go       # pgx 高吞吐写入
│   │
│   ├── auth/                       # 认证原语
│   │   ├── jwt.go                  # RS256 sign/verify
│   │   ├── totp.go                 # TOTP 验证
│   │   └── password.go             # Argon2id 哈希
│   │
│   ├── proxy/                      # 协议代理引擎
│   │   ├── ssh/
│   │   │   ├── server.go           # SSH daemon
│   │   │   ├── session.go          # 每连接 session
│   │   │   └── recorder.go         # asciicast 录制
│   │   ├── mysql/
│   │   │   ├── proxy.go            # MySQL 协议代理
│   │   │   └── auditor.go
│   │   ├── postgres/
│   │   │   ├── proxy.go            # PG 协议代理
│   │   │   └── auditor.go
│   │   ├── rdp/
│   │   │   ├── proxy.go            # Guacamole 桥接
│   │   │   └── recorder.go
│   │   └── websocket/
│   │       ├── terminal.go         # WebSocket → PTY/SSH 桥接
│   │       └── replay.go           # 会话回放流
│   │
│   └── recorder/                   # 会话录制引擎
│       ├── cast.go                 # Asciicast v2 写入器
│       ├── storage.go              # 存储接口定义 (Storage Backend)
│       ├── storage_local.go       # 本地文件系统实现
│       ├── storage_s3.go          # S3 / MinIO 实现
│       └── storage_oss.go         # 阿里云 OSS 实现 (可选)
│
├── migrations/                     # goose SQL 迁移
│   ├── 00001_create_users.sql
│   ├── 00002_create_assets.sql
│   └── ...
│
├── configs/
│   ├── config.dev.yaml       # SQLite 模式 — 零依赖本地开发
│   └── config.prod.yaml      # PostgreSQL 模式 — 生产环境
│
├── deployments/
│   ├── docker-compose.yaml
│   └── guacd/                      # guacd sidecar 配置
│
├── go.mod
├── Makefile
└── README.md
```

---

### Phase B1: 基础设施

**目标**: 搭建项目骨架，实现认证授权系统和核心 CRUD API。

#### Task B1.1: 项目脚手架

- 初始化 Go module，创建 `cmd/` 和 `internal/` 目录结构
- 单二进制多角色启动：`turjmp --api --ssh-proxy --db-proxy --rdp-proxy`
- 引入核心依赖：gin, sqlx, koanf, zap, golang-jwt, casbin
- 编写 `configs/config.dev.yaml` 和配置加载代码 (koanf)
- 编写 `Makefile`（build, test, lint, migrate, run 命令）
- 配置 `golangci-lint` (.golangci.yml)
- QA: `make build` 编译所有二进制通过，无 lint 错误

#### Task B1.2: 数据库设计与迁移

- **多数据库支持**: 通过配置切换 SQLite 和 PostgreSQL
  - SQLite (`modernc.org/sqlite`): 纯 Go 无 CGO，单文件部署，适合轻量化场景（`config.yaml: database.driver: sqlite`）
  - PostgreSQL (`pgx/v5`): 生产环境，高并发，会话录像高吞吐写入（`config.yaml: database.driver: postgres`）
- **数据库抽象层**: `internal/repository/db.go`
  ```go
  // 根据配置返回对应的 *sqlx.DB
  func NewDB(cfg config.DatabaseConfig) (*sqlx.DB, error) {
      switch cfg.Driver {
      case "sqlite":   return sqlx.Open("sqlite", cfg.DSN)   // 如 file:turjmp.db?_journal=WAL
      case "postgres": return sqlx.Connect("pgx", cfg.DSN)   // 如 postgres://user:pass@host/turjmp
      }
  }
  ```
- **SQL 兼容性**: repository 层手写 SQL 时注意方言差异
  - 分页: SQLite `LIMIT x OFFSET y`, PG 同样支持
  - 布尔: SQLite `INTEGER 0/1`, PG `BOOLEAN true/false`
  - 自增主键: SQLite `INTEGER PRIMARY KEY AUTOINCREMENT` → PG `SERIAL` / `IDENTITY`
  - 时间: 统一使用 `TIMESTAMP` / `DATETIME`（goose 迁移中按方言分别处理或使用兼容语法）
- 编写所有核心表的 goose SQL 迁移文件（每表支持两种方言，或使用 Go 迁移做适配）
- 定义 domain 实体 struct（零依赖，纯 Go struct + db tag）
- 实现 repository 层接口和 sqlx 实现（手写 SQL + struct scan）
- docker-compose: SQLite 模式不需额外服务；PG 模式引入 PostgreSQL + Redis
- QA: `make migrate-up` 分别测试 SQLite 和 PG 两种模式，`make migrate-down` 可回滚

#### Task B1.3: 用户认证系统

- `internal/auth/password.go`：Argon2id 密码哈希 (golang.org/x/crypto/argon2)
- `internal/auth/jwt.go`：生成密钥对，实现 RS256 sign/verify
  - Access Token: 15min TTL（无状态，公钥验证）
  - Refresh Token: 7day TTL（数据库存储，支持旋转 + 重用检测）
- `internal/auth/totp.go`：MFA/TOTP 设置和验证 (pquerna/otp)
- `POST /api/v1/auth/login` — 用户名密码登录，返回 access + refresh token
- `POST /api/v1/auth/refresh` — token 刷新
- `POST /api/v1/auth/mfa/setup` — 生成 TOTP secret + QR code URL
- `POST /api/v1/auth/mfa/verify` — 验证 TOTP 码，激活 MFA
- Gin middleware: `auth.go`（JWT 解析 + 验证）, `rbac.go`（Casbin enforce）
- QA: 无 token 访问 API 返回 401，有 token 返回数据，MFA 未激活用户可正常登录

#### Task B1.4: RBAC 权限系统

- 引入 Casbin，编写 `rbac_model.conf`（支持 RESTful keyMatch2）
- 编写 Casbin sqlx adapter 初始化和策略预加载
- 用 Casbin middleware 保护所有 API 路由
- 默认角色: super_admin, admin, operator, auditor
- `GET/POST/PUT/DELETE /api/v1/roles` — 角色 CRUD
- `POST /api/v1/roles/:id/permissions` — 为角色配置权限
- QA: auditor 角色只能 GET sessions 不能 GET assets；operator 能查看资产不能删除

#### Task B1.5: 资产管理系统

- `internal/domain/asset.go`：Asset, Platform, Protocol, Account 实体
- Platform 种子数据：Linux(SSH), Windows(RDP), MySQL, PostgreSQL
- Asset CRUD API: `GET/POST/PUT/DELETE /api/v1/assets`
- Account CRUD API: `GET/POST/PUT/DELETE /api/v1/assets/:id/accounts`
  - 密码字段用 Argon2id 加密存储（或 AES-GCM 可逆加密用于自动注入）
- `GET /api/v1/assets/tree` — 资产树（按节点分组）
- QA: 创建 Linux 资产 + SSH 账号，API 返回完整资产树

#### Task B1.6: 授权与连接令牌

- AssetPermission CRUD: 用户/用户组 ←→ 资产/节点 ←→ 账号
- `POST /api/v1/authentication/connection-tokens/` — 签发连接令牌
  - 入参: asset_id, account_id, protocol, connect_method(web_cli/ssh_client/...)
  - 验证: 用户在有效期内有该资产的 connect 权限
  - 返回: token value (UUID) + expires_in (300s 默认)
- **代理-API 间认证**: 代理层调用 `/verify` 端点需要认证
  - 方案: 每个代理 daemon 持有预共享密钥 (shared secret) 或 mTLS 客户端证书
  - 配置 `proxy_auth_secret` 在 `config.yaml` 中，API server 和 proxy 共享
  - verify 端点校验 `X-Proxy-Auth: <secret>` header，拒绝非代理请求
- `POST /api/v1/authentication/super-connection-tokens/verify` — Token 验证（代理层调用）
  - 入参: token value
  - 认证: `X-Proxy-Auth` header + IP 白名单检查
  - 返回: user, asset(ip, port), account(username, secret, secret_type, su_info), gateway, command_filter_acls, expire_at
- 速率限制: 对 token 签发和 verify 端点实施 rate limiting (gin-contrib/ratelimit)
- session 管理: `POST /api/v1/sessions` (创建), `PATCH /api/v1/sessions/:id` (完成/失败)
- QA: 有权限用户签出 token 成功，无权限返回 403；token 过期返回 401；无 proxy-auth 调用 verify 返回 401

#### Task B1.7: 系统配置引擎（DB 驱动，前端可配）

> **核心设计**: 除启动必需的引导配置（DB 连接、监听端口、密钥路径）放在 `config.yaml` 外，其余所有运行时可变的配置存入数据库，由前端管理界面统一修改，修改后动态生效无需重启。

**配置边界**:
| 存储位置 | 内容 | 原因 |
|---|---|---|
| `config.yaml` | 数据库 DSN、监听地址/端口、proxy-auth secret、JWT 密钥路径、日志级别 | 启动引导必需，无法从 DB 读取 |
| DB `settings` 表 | 录像存储后端、连接限制、超时、ACL 默认规则、邮件/通知、品牌、LDAP/OAuth | 运行时可变，需前端管理 |

**数据模型** (`migrations/000xx_create_settings.sql`):
```sql
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,       -- 如 "recording.storage"
    value       TEXT NOT NULL,          -- JSON 值
    category    TEXT NOT NULL DEFAULT 'general',  -- general | security | recording | notification
    label       TEXT,                   -- 前端显示名
    description TEXT,                   -- 前端提示文字
    input_type  TEXT DEFAULT 'text',    -- text | number | select | toggle | secret
    options     TEXT,                   -- select 的可选项 JSON
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**配置热加载**: API server 维护内存缓存 `sync.Map`，`GET /api/v1/settings` 返回全量，`PUT /api/v1/settings/:key` 更新后刷新缓存。代理 daemon 定期（每 30s）从 API server 拉取配置变更。

**预置配置项**:
| key | 默认值 | 说明 |
|---|---|---|
| `recording.storage` | `local` | 录像存储后端 (local/s3/oss/cos) |
| `recording.local.path` | `./recordings` | 本地录像目录 |
| `recording.s3.endpoint` | — | S3/MinIO 地址 |
| `recording.s3.bucket` | `turjmp-sessions` | S3 bucket 名 |
| `recording.s3.access_key` | — | S3 密钥 (加密存储) |
| `recording.s3.secret_key` | — | S3 密钥 (加密存储) |
| `proxy.ssh.max_connections` | `100` | SSH 最大并发连接 |
| `proxy.ssh.idle_timeout` | `900` | SSH 空闲超时 (秒) |
| `proxy.db.max_connections` | `50` | 数据库代理最大连接 |
| `proxy.db.idle_timeout` | `1800` | 数据库空闲超时 |
| `proxy.rdp.max_connections` | `20` | RDP 最大并发连接 |
| `security.session_timeout` | `3600` | 会话最大时长 (秒) |
| `security.mfa_required` | `false` | 是否强制 MFA |
| `security.password_min_length` | `8` | 密码最小长度 |
| `sftp.max_file_size` | `1073741824` | SFTP 最大文件 (1GB) |
| `sftp.deny_paths` | `/etc/shadow,/etc/passwd` | SFTP 禁止路径 |
| `notification.smtp.host` | — | 邮件通知 SMTP |
| `branding.site_name` | `Turjmp` | 站点名称 |

**API**:
- `GET /api/v1/settings` — 全量配置（按 category 分组返回）
- `PUT /api/v1/settings/:key` — 更新单个配置（admin only，敏感字段加密存储）
- `GET /api/v1/settings/:key` — 获取单个配置

QA: 前端修改录像存储为 `s3` 并填写密钥后，新会话的录像写入 MinIO，无需重启服务。

#### Task B1.8: 生产基础设施

- **健康检查端点**: `GET /health` (活体检测 200), `GET /health/ready` (就绪检测, 含 DB/Redis 连通性)
- **优雅关闭**: 使用 `signal.NotifyContext` 捕获 SIGTERM/SIGINT
  - API server: `http.Server.Shutdown()` with 30s timeout
  - Proxy daemon: 关闭前等待活跃连接完成或超时 (connection draining)
- **速率限制**: gin-contrib/ratelimit — 登录端点 5 req/s, token 签发 10 req/s, verify 端点 50 req/s
- **连接数限制**: SSH/DB/RDP 代理配置 `max_connections`，超限拒绝新连接并返回错误
- **空闲超时**: SSH 会话 15min 空闲自动断开; DB 会话 30min; RDP 会话 60min
- **SSH Keepalive**: `ClientAliveInterval: 30s`, `ClientAliveCountMax: 3`
- **Prometheus 指标**: `GET /metrics` — HTTP 请求数/延迟、活跃会话数、代理连接数、token 签发数
- **结构化日志**: zap JSON 格式，支持 `SIGHUP` 动态调整日志级别
- QA: `curl /health` → 200; `kill -TERM` → graceful shutdown 日志; Prometheus 抓取 `/metrics` 有数据

---

### Phase B2: SSH 代理

**目标**: 实现完整的 SSH 代理，支持 Web 终端和 SSH 客户端两种接入方式。

#### Task B2.1: SSH 服务器基础

- **SSH 主机密钥管理**:
  - 首次启动自动生成 ED25519 + RSA 主机密钥对
  - 密钥存储到 `host_keys` 表（或本地文件 `./keys/ssh_host_*_key`）
  - 后续启动加载已有密钥，保证客户端指纹不变
  - 提供 API 查看主机指纹 (`GET /api/v1/settings/ssh-fingerprint`)
- 基于 `gliderlabs/ssh` 搭建 SSH daemon (监听 :2222)
- SSH 认证：PasswordCallback 接收 connection token 作为"密码"
  - 调用 API server 的 `/verify` 端点验证 token
  - 验证通过返回资产连接信息（地址/端口/账号/密码/网关）
- 实现资产选择交互式菜单（类似 JumpServer 的 TUI 菜单）
  - 登录后列出用户有权限的资产
  - 支持搜索过滤
- `cmd/turjmp/main.go --ssh-proxy`：启动 SSH daemon
- QA: `ssh -p 2222 token_xxx@localhost`，成功列出资产列表并连接

#### Task B2.2: SSH 隧道转发 (direct-tcpip)

- 拦截 `direct-tcpip` channel 请求（Jump Host 模式）
- 解包目标地址，ACL 检查，桥接 SSH channel ↔ TCP connection
- 支持直连和网关跳转模式
- QA: `ssh -J token@bastion:2222 root@target` 成功跳转到内网机器

#### Task B2.3: SSH 会话录制

- `internal/recorder/cast.go`：实现 Asciicast v2 JSON 写入器
  - 输出格式: `[timestamp, "o", "output_data\n"]`
  - 使用 `io.TeeReader` 从 PTY/SSH 输出流中捕获数据
- `internal/proxy/ssh/recorder.go`：在 SSH session handler 中集成录制

**存储后端抽象** (`internal/recorder/storage.go`):
```go
// StorageBackend 录像存储接口 — 所有后端实现此接口
type StorageBackend interface {
    // Put 上传录像文件，返回访问 URL
    Put(ctx context.Context, sessionID string, r io.Reader, size int64) (url string, err error)
    // Get 获取录像文件流（回放用）
    Get(ctx context.Context, sessionID string) (io.ReadCloser, error)
    // Delete 删除录像文件
    Delete(ctx context.Context, sessionID string) error
    // URL 生成可公开访问的下载/播放地址（支持签名 URL）
    URL(ctx context.Context, sessionID string, expire time.Duration) (string, error)
}
```

**内置实现**:
| 后端 | 配置值 | 实现 | 适用场景 |
|---|---|---|---|
| 本地文件 | `local` | `storage_local.go` — `./recordings/` 目录 | 开发 / 单机部署 |
| S3 / MinIO | `s3` | `storage_s3.go` — `aws-sdk-go-v2` | 生产 / 集群部署 |
| 阿里云 OSS | `oss` | `storage_oss.go` — `aliyun-oss-go-sdk` | 国内云环境 |
| 腾讯云 COS | `cos` | (预留，按需实现) | 国内云环境 |

**配置**: `config.yaml`
```yaml
recording:
  storage: s3                     # local | s3 | oss | cos
  local:
    path: ./recordings
  s3:
    endpoint: http://minio:9000   # MinIO 地址 (生产可用 AWS S3)
    bucket: turjmp-sessions
    access_key: ${S3_ACCESS_KEY}
    secret_key: ${S3_SECRET_KEY}
    use_ssl: false
  oss:
    endpoint: oss-cn-hangzhou.aliyuncs.com
    bucket: turjmp-sessions
    access_key: ${OSS_ACCESS_KEY}
    secret_key: ${OSS_SECRET_KEY}
```

- 录制时: CastWriter → `io.Pipe()` Writer → goroutine 后台 `StorageBackend.Put()` → 流式上传
- `POST /api/v1/sessions/:id/recording` — 录制完成后更新会话元数据
- 回放: API 调用 `StorageBackend.URL()` 生成签名 URL 返回前端，前端直接加载
- QA: 分别配置 local/s3/oss 模式，完成 SSH 会话后录制文件存入对应后端，回放正常

#### Task B2.4: WebSocket 终端桥接

- `internal/proxy/websocket/terminal.go`
- WebSocket endpoint: `GET /ws/terminal/?token=<connection_token>`
  - Upgrade HTTP → WebSocket (coder/websocket)
  - 验证 token → 获取资产信息 → 建立 SSH 连接（x/crypto/ssh client）
  - 双 goroutine 桥接:
    - WS msg → SSH stdin
    - SSH stdout/stderr → WS msg
  - 支持 PTY resize 消息（传入 rows/cols）
- 集成 Asciicast 录制
- QA: 浏览器连接 WebSocket，发送 `ls -la`，收到输出，发送 resize 信号 PTY 尺寸变化

#### Task B2.5: 命令过滤 ACL

- 实现 CommandFilterACL 引擎 (白名单/黑名单正则)
- SSH session 中拦截命令输入，匹配 ACL 规则
  - action=deny → 拒绝执行，返回提示
  - action=review → 允许但标记待审核
  - action=allow → 允许
- QA: 设置 `rm -rf` 黑名单，用户执行该命令时被拦截

#### Task B2.6: SFTP 文件传输

- 基于 `gliderlabs/ssh` 内置的 `"sftp"` 子系统 + `github.com/pkg/sftp`
- SFTP 会话处理:
  - Token 验证 → 建立 SSH 连接到目标资产 → 创建 SFTP client
  - 文件操作审计: 记录 upload/download/delete/rename 到 `audit_logs`
- 文件传输限制:
  - 最大文件大小限制 (配置项 `sftp_max_file_size`)
  - 禁止路径 (配置项 `sftp_deny_paths`: 如 `/etc/shadow`)
- Web 文件管理 (前端 Phase F2): 资产详情页 "文件管理" tab → 调用 SFTP API
- QA: `sftp -P 2222 token@bastion` 连接成功, `get/put` 文件正常, audit_logs 有记录

---

### Phase B3: 数据库代理 (MySQL / PostgreSQL)

**目标**: 实现 MySQL 和 PostgreSQL 协议代理，支持 Web SQL 终端。

#### Task B3.1: MySQL 协议代理

- `internal/proxy/mysql/proxy.go`
- 基于 `go-mysql-org/go-mysql/server` 搭建 Fake MySQL Server (监听 :3307)
- 认证方式: 用户传入 connection token 作为"数据库密码"
  - 验证 token → 获取真实 MySQL 凭据
- 实现 `server.Handler` 接口：
  - `HandleQuery(query)` → 转发到真实 MySQL → 返回结果
  - `HandleStmtPrepare/Execute/Close` → 预处理语句转发
- 透明代理模式:
  ```
  客户端 → Proxy (3307) → 拦截握手 → 修改 capability flags → 中继到真实 MySQL (3306)
  ```
- 查询审计: `internal/proxy/mysql/auditor.go`
  - 记录每条 SQL 语句、执行时间、影响行数到 `audit_logs` 表
  - 支持敏感数据脱敏规则
- QA: `mysql -h proxy -P 3307 -u token_xxx`，执行 SELECT 查询正常返回，audit_logs 中有记录

#### Task B3.2: PostgreSQL 协议代理

> **⚠️ 关键设计说明**: PostgreSQL 有线协议不是简单 TCP 流。它包含有状态的认证握手（SCRAM-SHA-256/md5）、带内 `ParameterStatus`、扩展查询协议（Parse/Bind/Describe/Execute/Sync 流式消息）、带外 `CancelRequest`、以及长度前缀消息。**`io.Copy` 不能用于 PG 代理** —— 必须构建协议状态机。

- `internal/proxy/postgres/proxy.go`
- 基于 `pgproto3.NewBackend() / NewFrontend()` 实现三层状态机:

**状态机阶段**:
1. **Startup Phase**: 接收 `StartupMessage` (或 `SSLRequest` + `CancelRequest`)
   - 拒绝 SSL（回 `'N'`），接收真实 StartupMessage
   - 解析 user、database 参数
   - 从 user 字段提取 token → 调用 API server `/verify` 获取真实凭据
2. **Authentication Phase**: 转发认证消息
   - Proxy 同时持有两条链路: `client ↔ proxy` (Backend 侧), `proxy ↔ real PG` (Frontend 侧)
   - 处理 `AuthenticationSASL` / `AuthenticationMD5Password` 等消息
   - 拦截并修改 `AuthenticationOk` 后的 `ParameterStatus` → 注入自定义参数（如 `bastion_session_id`）
3. **Query Phase**: 双向消息路由
   - 简单查询协议 (`Query 'Q'`): 解析 SQL → 审计 → 转发到 real PG → 审计结果
   - 扩展查询协议 (`Parse/Bind/Describe/Execute/Sync`): 跟踪 prepared statement 状态，审计执行
   - `CopyIn/CopyOut`: 流式透传（不解析内容，避免内存膨胀）
   - `Terminate 'X'`: 关闭两条链路

- 查询审计: `internal/proxy/postgres/auditor.go`
  - 截获 SQL 文本 → 写入 `audit_logs`（批处理，避免阻塞代理）
  - 支持敏感数据脱敏规则（如遮罩 `credit_card` 列）
- 监听端口: `:5437`
- **简化替代方案**: 如果完整状态机实现周期过长，Phase 1 先仅支持 usql Web 终端 (B3.3)，原生 PG 客户端代理放入 Phase B5 作为 Magnus 模式实现
- QA: `psql -h proxy -p 5437 -U token_xxx -d targetdb`，SELECT 返回数据，audit_logs 有记录；CancelRequest 能终止正在运行的查询

#### Task B3.3: WebSocket 数据库终端

- `GET /ws/db-terminal/?token=<connection_token>`
- 方案: 使用 `usql` 子进程作为数据库 CLI
  ```
  浏览器(xterm.js) → WebSocket → Go Server → usql subprocess PTY → 真实 DB
  ```
- 流程:
  1. Token 验证 → 获取 DB 类型(mysql/pg)、地址、凭据
  2. 构造 usql DSN: `mysql://user:pass@host:port/db`
  3. `exec.Command("usql", dsn)` + PTY 分配
  4. 双向桥接: WS ↔ PTY (stdin/stdout)
  5. PTY resize 转发
- 优势: 一个 usql 统一支持 MySQL/PostgreSQL/Oracle/SQL Server 等
- QA: 浏览器 Web 终端连接 MySQL 资产，执行 SQL，结果显示在终端中

---

### Phase B4: RDP 代理

**目标**: 实现 RDP 协议的 Web 代理和会话录制。

#### Task B4.1: guacd 集成

- 引入 `wwt/guac` Guacamole 协议 Go 客户端
- docker-compose 部署 `guacd:1.5` 作为 sidecar
- `internal/proxy/rdp/proxy.go`：
  - 建立到 guacd 的 TCP 连接
  - 握手: `guac.NewStream(tcpConn)` → `stream.Handshake(config)`
  - config.Parameters: hostname, port, username, password, security, ignore-cert
- QA: guacd 健康检查通过，连接 RDP 目标服务器成功

#### Task B4.2: RDP WebSocket 桥接

- `GET /ws/rdp/?token=<connection_token>`
- 流程:
  1. Token 验证 → 获取 RDP 凭据 → 连接 guacd
  2. 创建 Guacamole Tunnel
  3. Goroutine 1: WebSocket → guacd (键盘/鼠标事件)
  4. Goroutine 2: guacd → WebSocket (帧缓冲/音频)
- 前端使用 Guacamole JS client 渲染 RDP 画面
- QA: 浏览器连接 RDP WebSocket，看到 Windows 桌面，能操作鼠标键盘

#### Task B4.3: RDP 会话录制（可选增强）

- guacd 自带屏幕录制能力（通过 recording path 配置）
- 录制文件转储: guacd → `StorageBackend.Put()`（复用 B2.3 定义的存储接口）
- 会话回放: 使用 Guacamole 的 playback 协议，视频文件通过 `StorageBackend.URL()` 获取
- **存储后端统一**: RDP 录制文件同样走 local/s3/oss 存储接口，与会话录像共用配置
- QA: RDP 会话完成后，录制文件存入对应存储后端且可回放

---

### Phase B5: 原生客户端透传

**目标**: 让原生客户端 (ssh, Navicat, mstsc, DBeaver) 能直接连接代理，实现透明透传。

#### Task B5.1: 多协议端口监听器 (Multiplexer)

- 参考 Teleport `lib/multiplexer/multiplexer.go` 实现协议检测
- 单一端口检测 SS/TLS/PG/TDS 协议（可选）
- 或独立端口: `:2222` (SSH), `:3307` (MySQL), `:5437` (PG), `:3389` (RDP)
- QA: SSH 客户端连接 2222 正确路由到 SSH handler，MySQL 客户端到 3307 路由到 MySQL handler

#### Task B5.2: Magnus 模式 — 数据库 TCP 透明代理

- 对于 Navicat/DBeaver 等客户端，连接: `proxy:3307` (MySQL) / `proxy:5437` (PG)
- **Token 传递方式**: 
  - MySQL: 将 token 嵌入 **username 字段**（格式: `username#token_uuid`），保留原始 `password` 字段给真实数据库密码
    - Proxy 在握手时拦截 username，解析出 user + token，验证后使用真实凭据连接目标
  - PostgreSQL: token 嵌入 **username 字段**（格式: `username#token_uuid`），在 StartupMessage 中解析
  - 此方式兼容所有标准数据库客户端（Navicat, DBeaver, DataGrip, mysql cli, psql）
- MySQL 原生握手流程:
  ```
  客户端 → Proxy (3307): HandshakeV10 + auth_response
  Proxy: 解析 username → 分离 user#token
  Proxy → API: 验证 token → 获取真实 user/pass/host
  Proxy → Real MySQL (3306): 使用真实凭据建立新连接
  Proxy → Proxy 内部状态机: 桥接两条连接
  Proxy → 客户端: 转发握手结果 + OK packet
  后续: 双向转发 MySQL 协议包（COM_QUERY 等通过 Handler 接口审计）
  ```
- SQL 审计: 协议感知代理 — 解析 `COM_QUERY` 包 → 写入 `audit_logs`
- 连接池: 代理到目标数据库启用连接池 (connpool)，复用 TCP 连接
- QA: Navicat 连接 proxy:3307，host 填 localhost，user 填 `realuser#token_uuid`，password 填真实密码，成功操作远程数据库

#### Task B5.3: Razor 模式 — RDP 原生客户端接入

> **⚠️ 重要**: RDP 不是透明协议。它使用 TLS/CredSSP 加密，无法在不理解 RDP 协议的情况下做"先验证 token 再转发"。因为 Go 没有生产级 RDP 协议库，采用**动态端口转发 + guacd** 混合方案。

- **方案: 动态端口隧道**

  ```
  浏览器: 用户点"下载 .rdp 文件"
  API: 分配临时 TCP 端口 (例 :50001)，创建 RDP 隧道 session
  用户: 双击 .rdp 文件 → mstsc 连接 proxy:50001
  Proxy: :50001 监听器 → guacd → FreeRDP → 目标 Windows
  ```

- 具体流程:
  1. 用户从 Web 界面请求 RDP 原生连接
  2. API server 签发 token + 分配临时端口 (端口池 50000-50999)
  3. RDP proxy 在分配的端口上启动动态监听器 (绑定该端口)
  4. 生成 `.rdp` 文件: `full address:s:proxy_host:50001` + `username:s:token_xxx`
  5. 用户在本地双击 `.rdp` 文件，mstsc 连接到 proxy
  6. Proxy 在 RDP 连接建立初期 (X.224 阶段) 提取 username 字段中的 token
  7. 验证 token → 建立 guacd 会话 → FreeRDP 连接到真实 Windows Server
  8. 会话结束后释放端口

- **录制**: 通过 guacd 的 recording path 功能录制屏幕
- **安全**: 临时端口仅在 token 有效期内监听（默认 5 分钟），分配时绑定 token → 连接建立后端口关闭
- QA: 下载 .rdp 文件 → 双击启动 → mstsc 连接成功 → 操作 Windows 桌面 → 会话可回放

#### Task B5.4: 原生 RDP 备选方案 — Apache Guacamole 原生客户端

- 如果动态端口方案复杂度过高，回退方案:
  - 所有 RDP 访问统一走 Web 浏览器 (Guacamole JS Client)
  - 浏览器内全屏体验已足够满足大多数需求
  - 原生 RDP 客户端接入推迟到 v2.0
- QA: 不适用（如采用回退方案则跳过 B5.3）

#### Task B5.5: SDK 连接文件生成

- `POST /api/v1/authentication/connection-tokens/sdk-url` — 返回原生客户端连接信息
- SSH: `ssh -J token@bastion:2222 root@target`
- MySQL: `mysql -h bastion -P 3307 -u token_xxx -p`
- PG: `psql -h bastion -p 5437 -d token_xxx`
- RDP: 生成 .rdp 文件下载
- 生成 `jms://` 协议 URL（可与桌面客户端集成）
- QA: API 返回的连接字符串可直接在终端中使用

---

## 前端实现计划

### 前端技术栈

| 组件 | 库 |
|---|---|
| 框架 | Vue 3.5+ (Composition API + `<script setup>`) |
| 语言 | TypeScript strict |
| 构建 | Vite 6 |
| 路由 | Vue Router 4 |
| 状态管理 | Pinia |
| HTTP | Axios + 拦截器 (JWT 自动刷新) |
| UI 框架 | Element Plus (中文生态成熟) 或 Naive UI |
| 终端模拟 | xterm.js 5 + @xterm/addon-fit + @xterm/addon-web-links |
| RDP Web | @microsoft/guacamole-common-js 或 Apache Guacamole JS |
| 会话回放 | asciinema-player |
| 代码规范 | ESLint + Prettier |

### 项目结构

```
web/
├── src/
│   ├── api/              # Axios 封装 + API 模块
│   │   ├── client.ts     # Axios 实例 (base URL, interceptor)
│   │   ├── auth.ts       # 登录/登出/MFA
│   │   ├── assets.ts     # 资产 CRUD
│   │   ├── users.ts      # 用户 CRUD
│   │   ├── permissions.ts # 授权管理
│   │   ├── sessions.ts   # 会话管理
│   │   └── tokens.ts     # 连接令牌
│   ├── router/
│   │   └── index.ts      # 路由定义 + 导航守卫
│   ├── stores/           # Pinia stores
│   │   ├── auth.ts       # 用户状态 + token
│   │   └── app.ts        # 全局设置
│   ├── views/            # 页面组件
│   │   ├── login/        # 登录页 + MFA
│   │   ├── dashboard/    # 仪表盘
│   │   ├── assets/       # 资产管理
│   │   ├── users/        # 用户管理
│   │   ├── permissions/  # 授权管理
│   │   ├── sessions/     # 在线会话 + 历史
│   │   └── terminal/     # Web 终端组件
│   ├── components/       # 可复用组件
│   │   ├── layout/       # 布局 (侧边栏/顶栏/内容区)
│   │   ├── asset-tree/   # 资产树组件
│   │   ├── terminal/     # 终端嵌入组件
│   │   └── rdp-viewer/   # RDP 查看器组件
│   ├── composables/      # 组合式函数
│   │   ├── useTerminal.ts
│   │   ├── useRDP.ts
│   │   └── useSessionReplay.ts
│   └── utils/
│       └── download.ts   # RDP 文件下载等
├── public/
│   └── favicon.ico
├── index.html
├── vite.config.ts
├── tsconfig.json
├── package.json
└── .eslintrc.cjs
```

---

### Phase F1: 管理控制台

**目标**: 实现完整的资产管理后台，对标 JumpServer Lina。

#### Task F1.1: 项目脚手架

- `npm create vite@latest web -- --template vue-ts`
- 引入 Element Plus / Naive UI
- 引入 Vue Router, Pinia, Axios
- 配置 ESLint + Prettier
- 实现基础布局: 侧边栏导航 + 顶栏 (用户信息/退出) + 内容区
- 路由守卫: 未登录跳转 /login，token 过期自动刷新
- QA: `npm run dev` 启动正常，路由切换流畅

#### Task F1.2: 登录与 MFA

- 登录页面: 用户名 + 密码 + 可选 MFA 验证码
  - 第一步: 用户名密码验证，返回 `require_mfa: true/false`
  - 第二步: 如需要 MFA，显示 6 位验证码输入框
- 登录成功后存储 access token + refresh token
- Axios 拦截器:
  - 401 时自动用 refresh token 刷新
  - 并发请求共享刷新 Promise（只发起一次刷新）
- 登出: 清除 token，跳转登录页
- QA: 正确凭据登录成功进入 Dashboard，错误显示提示；MFA 激活用户显示第二步

#### Task F1.3: 资产管理

- 资产列表页: 表格 + 分页 + 搜索 + 过滤 (平台/协议/状态)
- 资产详情/编辑页: 基本信息 + 协议配置 + 账号管理
- 资产树组件: 树形结构显示资产分组
- 平台管理: 查看/添加平台模板
- 账号管理: 添加/编辑 SSH 密钥或密码，密码脱敏显示
- QA: 创建资产 → 列表可见 → 编辑 → 删除，全部正常

#### Task F1.4: 用户与权限管理

- 用户列表: CRUD + 角色分配 + MFA 状态
- 角色管理: 查看/编辑角色的 Casbin 权限策略
- 授权管理 (AssetPermission):
  - 创建授权: 选择用户/用户组 → 选择资产/节点 → 选择账号 → 设置有效期
  - 授权列表: 查看/编辑/删除授权
  - 支持到期自动失效和手动失效
- QA: 创建授权后，被授权用户可看到对应资产

#### Task F1.5: 仪表盘与会话审计

- 仪表盘: 总资产数、在线会话数、今日会话数、活跃用户
- 在线会话列表: 实时显示当前活跃连接 (WebSocket 推送)
  - 管理员可强制断开会话
- 历史会话: 日期过滤 + 用户/资产搜索
- 会话详情: 开始/结束时间、协议、录制文件、命令记录
- QA: 仪表盘数据准确，在线会话实时刷新

#### Task F1.6: 系统配置管理

- 系统配置页面: 分类 Tab 展示所有可配置项
  - **录像存储**: 后端选择 (local/s3/oss) + 对应参数配置（endpoint/bucket/密钥）
  - **连接限制**: SSH/DB/RDP 最大并发连接数、空闲超时、会话最大时长
  - **安全策略**: MFA 强制开关、密码最小长度、登录失败锁定策略
  - **SFTP 控制**: 最大文件大小、禁止路径列表
  - **通知设置**: SMTP 服务器、发件人、邮件模板
  - **品牌定制**: 站点名称、Logo、主题色
  - **LDAP/OAuth**: 外部认证源配置（按需）
- 配置组件: 根据 `input_type` 动态渲染 (text/number/toggle/select/secret)
- 修改后即时保存 + 提示生效时间（代理 daemon 30s 内同步）
- 敏感字段 (S3 密钥等) 用密码框 + 写入后不可读回，显示为 `****`
- QA: 修改站点名称 → 页面标题立即变化；切换录像存储为 s3 → 新会话录像写入 MinIO

---

### Phase F2: Web 终端访问

**目标**: 实现浏览器内终端访问，对标 JumpServer Luna。

#### Task F2.1: xterm.js 终端组件

- `composables/useTerminal.ts`
- 集成 xterm.js + addon-fit (自适应大小) + addon-web-links (链接可点击)
- Theme: 深色主题 (Dracula / One Dark)
- 连接流程:
  1. 请求 `/connection-tokens/` 获取 token
  2. 打开 WebSocket: `ws://{host}/ws/terminal/?token={token}`
  3. WebSocket onmessage → terminal.write(data)
  4. terminal.onData(data) → WebSocket send(data)
  5. terminal.onResize → WebSocket send resize JSON
- 终端工具栏: 资产名称、会话时长、复制/粘贴、断开连接
- 支持多 Tab 终端（多个资产同时打开）
- QA: 点击 Web 终端 → 新窗口打开 → SSH 到目标服务器 → 执行命令 → 显示正常

#### Task F2.2: 数据库 Web 终端

- 复用 xterm.js 组件，连接到 `/ws/db-terminal/?token={token}`
- 终端内显示 usql 交互式 SQL 界面
- 支持自动补全?（usql 内置）
- 数据库连接 Dropdown 选择器（在终端界面上方）
- QA: 打开 MySQL Web 终端 → 执行 `SHOW TABLES;` → 显示结果

#### Task F2.3: 资产快速连接入口

- 资产列表中每行: "Web 终端" 按钮 → 打开终端窗口
- 资产详情页: 协议切换 tab (SSH / DB / RDP) → 对应终端
- 仪表盘快捷入口: 最近访问的资产列表
- QA: 从资产列表一键进入 SSH Web 终端

---

### Phase F3: 会话回放 & 原生客户端接入

#### Task F3.1: 会话回放

- `composables/useSessionReplay.ts`
- 引入 `asciinema-player` npm 包
- 回放页面:
  - 时间轴 + 播放/暂停/快进/倍速
  - 进度条可拖拽
  - 显示会话元数据 (用户/资产/时间/命令数)
- 从后端获取 cast 文件 URL (S3 presigned 或 本地 API)
- QA: 完成一次 SSH 会话后，在回放页看到完整命令回放

#### Task F3.2: RDP Web 客户端

- `composables/useRDP.ts`
- 引入 Guacamole JS client (从 WSS 连接)
- RDP 查看器页面:
  - 全屏 RDP 画面
  - 工具栏: 断开、全屏、剪贴板同步
- 连接流程:
  1. 请求 token
  2. 创建 Guacamole Client → connect(`ws://{host}/ws/rdp/?token={token}`)
  3. 绑定 onSync 渲染画面到 canvas
- QA: 浏览器打开 RDP 连接，看到 Windows 桌面，能操作

#### Task F3.3: 原生客户端连接入口

- 资产详情页 "下载连接文件" 按钮:
  - SSH: 显示 `ssh -J token@bastion:2222 root@target`，一键复制
  - RDP: 下载 `.rdp` 文件
  - MySQL: 显示 `mysql -h bastion -P 3307 -u token_xxx -p`，一键复制
  - PG: 显示 `psql -h bastion -p 5437 -d token_xxx`，一键复制
- 连接文件有效期与 token 一致，过期后提示重新下载
- QA: 下载 RDP 文件，双击用 mstsc 打开，成功连接远程 Windows

---

## API 设计纲要

### 认证

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | 用户名密码登录 |
| POST | `/api/v1/auth/refresh` | 刷新 Access Token |
| POST | `/api/v1/auth/logout` | 登出 |
| POST | `/api/v1/auth/mfa/setup` | 生成 MFA 密钥 + QR |
| POST | `/api/v1/auth/mfa/verify` | 验证并激活 MFA |

### 用户与权限

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/users` | 用户列表/创建 |
| GET/PUT/DELETE | `/api/v1/users/:id` | 用户详情/编辑/删除 |
| GET/POST | `/api/v1/roles` | 角色列表/创建 |
| GET/PUT/DELETE | `/api/v1/roles/:id` | 角色详情/编辑/删除 |
| GET/POST | `/api/v1/permissions` | 授权列表/创建 |
| PUT/DELETE | `/api/v1/permissions/:id` | 授权编辑/删除 |

### 资产

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/assets` | 资产列表/创建 |
| GET/PUT/DELETE | `/api/v1/assets/:id` | 资产详情/编辑/删除 |
| GET | `/api/v1/assets/tree` | 资产树 |
| GET/POST | `/api/v1/assets/:id/accounts` | 账号列表/添加 |
| PUT/DELETE | `/api/v1/assets/:id/accounts/:aid` | 编辑/删除账号 |
| GET | `/api/v1/platforms` | 平台模板列表 |

### 连接令牌

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/authentication/connection-tokens/` | 签发连接令牌 |
| POST | `/api/v1/authentication/super-connection-tokens/verify/` | 代理层验证令牌 |
| GET | `/api/v1/authentication/connection-tokens/sdk-url` | 获取原生客户端连接信息 |

### 会话与审计

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/sessions` | 会话列表 |
| GET | `/api/v1/sessions/:id` | 会话详情 |
| PATCH | `/api/v1/sessions/:id` | 标记完成/强制断开 |
| GET | `/api/v1/sessions/:id/recording` | 获取录像播放 URL |
| GET | `/api/v1/audit-logs` | 审计日志列表 |

### WebSocket (Gin 直接处理升级)

| Path | Protocol | Description |
|------|----------|-------------|
| `/ws/terminal/` | coder/websocket | SSH Web 终端 (xterm.js) |
| `/ws/db-terminal/` | coder/websocket | 数据库 Web 终端 (usql) |
| `/ws/rdp/` | wwt/guac → Guacamole | RDP Web 客户端 |

---

## 部署架构

所有服务通过 `docker compose` 一键部署。提供两套 profile：**`lite`**（SQLite 轻量模式）和 **`full`**（PostgreSQL 全功能模式）。

### Dockerfile（多阶段构建）

```dockerfile
# ============ 构建阶段 ============
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG BUILD_TAG=dev
RUN make build BUILD_TAG=${BUILD_TAG}

# ============ 运行阶段 ============
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata usql openssh-client
COPY --from=builder /src/bin/* /usr/local/bin/
COPY --from=builder /src/migrations /migrations
COPY --from=builder /src/configs /etc/turjmp/
COPY --from=builder /src/web/dist /var/www/turjmp/
EXPOSE 8080 2222 3307 5437 3389
ENTRYPOINT ["/usr/local/bin/turjmp"]
```

### 目录结构

```
deployments/
├── docker-compose.yaml        # 主编排文件
├── docker-compose.lite.yaml   # lite profile override
├── docker-compose.full.yaml   # full profile override
├── Dockerfile                  # Go 多阶段构建
├── nginx/
│   └── default.conf            # Nginx 反向代理 + 前端静态文件
├── config/
│   ├── config.lite.yaml       # SQLite 模式配置
│   └── config.full.yaml       # PG 模式配置
└── scripts/
    ├── init-db.sh             # PG 初始化脚本
    └── init-minio.sh          # MinIO bucket 创建
```

### docker-compose.yaml

```yaml
version: "3.9"

x-common: &common
  restart: unless-stopped
  logging:
    driver: json-file
    options: { max-size: "10m", max-file: "3" }

x-health-defaults: &health_defaults
  interval: 10s
  timeout: 5s
  retries: 3
  start_period: 15s

services:
  # ============================================================
  # 反向代理 (所有模式必需)
  # ============================================================
  nginx:
    <<: *common
    image: nginx:1.27-alpine
    ports:
      - "443:443"                              # HTTPS (Web + WS)
      - "${SSH_PORT:-2222}:2222"               # SSH 客户端通道
      - "${MYSQL_PORT:-3307}:3307"             # MySQL 客户端通道
      - "${PG_PORT:-5437}:5437"                # PostgreSQL 客户端通道
      - "${RDP_PORT:-33891}:33891"             # RDP 动态端口范围入口
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./ssl:/etc/nginx/ssl:ro                # TLS 证书
      - web_dist:/var/www/turjmp:ro            # 前端静态文件
    depends_on:
      api-server:  { condition: service_healthy }
      ssh-proxy:   { condition: service_started }
      db-proxy:    { condition: service_started }
      rdp-proxy:   { condition: service_started }
    networks: [turjmp]

  # ============================================================
  # API Server (所有模式必需)
  # ============================================================
  api-server:
    <<: *common
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    command: --config /etc/turjmp/config.yaml --api
    environment:
      TURJMP_CONFIG: /etc/turjmp/config.yaml
      TURJMP_DATABASE_DRIVER: ${DATABASE_DRIVER:-sqlite}
    volumes:
      - ./config/config.${PROFILE:-lite}.yaml:/etc/turjmp/config.yaml:ro
      - api_data:/data                        # SQLite 文件 + 本地录像
      - ssh_keys:/keys                        # SSH 主机密钥持久化
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/health"]
    networks: [turjmp]

  # ============================================================
  # SSH 代理 (所有模式必需)
  # ============================================================
  ssh-proxy:
    <<: *common
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    command: --config /etc/turjmp/config.yaml --ssh-proxy
    volumes:
      - ./config/config.${PROFILE:-lite}.yaml:/etc/turjmp/config.yaml:ro
      - ssh_keys:/keys:ro
      - api_data:/data                        # 会话录像共享
    depends_on:
      api-server: { condition: service_healthy }
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "nc", "-z", "localhost", "2222"]
    networks: [turjmp]

  # ============================================================
  # 数据库代理 (所有模式必需)
  # ============================================================
  db-proxy:
    <<: *common
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    command: --config /etc/turjmp/config.yaml --db-proxy
    volumes:
      - ./config/config.${PROFILE:-lite}.yaml:/etc/turjmp/config.yaml:ro
      - api_data:/data
    depends_on:
      api-server: { condition: service_healthy }
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "nc", "-z", "localhost", "3307"]
    networks: [turjmp]

  # ============================================================
  # RDP 代理 (所有模式必需)
  # ============================================================
  rdp-proxy:
    <<: *common
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    command: --config /etc/turjmp/config.yaml --rdp-proxy
    volumes:
      - ./config/config.${PROFILE:-lite}.yaml:/etc/turjmp/config.yaml:ro
      - api_data:/data
    depends_on:
      api-server: { condition: service_healthy }
      guacd:      { condition: service_healthy }
    networks: [turjmp]

  # ============================================================
  # guacd — RDP 协议引擎 (所有模式必需)
  # ============================================================
  guacd:
    <<: *common
    image: guacamole/guacd:1.5.5
    volumes:
      - guacd_recordings:/recordings         # RDP 屏幕录制
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "nc", "-z", "localhost", "4822"]
    networks: [turjmp]

  # ============================================================
  # PostgreSQL + Redis — full profile 专用
  # ============================================================
  postgres:
    <<: *common
    image: postgres:16-alpine
    profiles: ["full"]
    environment:
      POSTGRES_DB: turjmp
      POSTGRES_USER: turjmp
      POSTGRES_PASSWORD: ${PG_PASSWORD:-changeme}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./scripts/init-db.sh:/docker-entrypoint-initdb.d/init.sh:ro
    healthcheck:
      <<: *health_defaults
      test: ["CMD-SHELL", "pg_isready -U turjmp -d turjmp"]
    networks: [turjmp]

  redis:
    <<: *common
    image: redis:7-alpine
    profiles: ["full"]
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "redis-cli", "ping"]
    networks: [turjmp]

  # ============================================================
  # MinIO — 对象存储 (full profile 专用, lite 模式使用本地目录)
  # ============================================================
  minio:
    <<: *common
    image: minio/minio:RELEASE.2024-12-18T13-15-44Z
    profiles: ["full"]
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_USER:-admin}
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD:-changeme}
    volumes:
      - minio_data:/data
    healthcheck:
      <<: *health_defaults
      test: ["CMD", "mc", "ready", "local"]
    networks: [turjmp]

  # MinIO 初始化 — 创建 bucket
  minio-init:
    image: minio/mc:latest
    profiles: ["full"]
    entrypoint: >
      /bin/sh -c "
      mc alias set local http://minio:9000 ${MINIO_USER:-admin} ${MINIO_PASSWORD:-changeme};
      mc mb --ignore-existing local/turjmp-sessions;
      mc anonymous set download local/turjmp-sessions;
      "
    depends_on:
      minio: { condition: service_healthy }
    networks: [turjmp]

volumes:
  api_data:           # SQLite DB + 本地录像 (lite 模式)
  ssh_keys:           # SSH 主机密钥
  web_dist:           # 前端构建产物
  guacd_recordings:   # RDP 录制暂存
  pgdata:             # PostgreSQL 数据
  redis_data:         # Redis 持久化
  minio_data:         # MinIO 对象存储

networks:
  turjmp:
    driver: bridge
```

### 部署命令

```bash
# ===== 轻量模式 (SQLite, 无需 PG/Redis/MinIO) =====
PROFILE=lite docker compose --profile lite up -d
# 服务: nginx + api-server + ssh-proxy + db-proxy + rdp-proxy + guacd
# 存储: SQLite 单文件 + 本地目录录像

# ===== 全功能模式 (PostgreSQL + Redis + MinIO) =====
PROFILE=full docker compose --profile full up -d
# 所有服务启动

# ===== 查看状态 =====
docker compose ps
docker compose logs -f api-server

# ===== 数据库迁移 =====
docker compose exec api-server turjmp --config /etc/turjmp/config.yaml --migrate up

# ===== 停止 =====
docker compose down           # 保留数据卷
docker compose down -v        # 清除所有数据
```

### Nginx 反向代理配置 (`deployments/nginx/default.conf`)

```nginx
upstream api { server api-server:8080; }
upstream ssh_proxy { server ssh-proxy:2222; }
upstream db_proxy_mysql { server db-proxy:3307; }
upstream db_proxy_pg { server db-proxy:5437; }
upstream rdp_proxy { server rdp-proxy:33891; }

server {
    listen 443 ssl http2;
    server_name turjmp.local;

    ssl_certificate     /etc/nginx/ssl/turjmp.crt;
    ssl_certificate_key /etc/nginx/ssl/turjmp.key;

    # 前端 SPA
    root /var/www/turjmp;
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API
    location /api/ {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # WebSocket 终端
    location /ws/ {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}

# SSH 客户端 TCP 代理 (stream 模块)
stream {
    upstream ssh_backend { server ssh-proxy:2222; }
    upstream mysql_backend { server db-proxy:3307; }
    upstream pg_backend { server db-proxy:5437; }
    upstream rdp_backend { server rdp-proxy:33891; }

    server { listen 2222; proxy_pass ssh_backend; proxy_connect_timeout 30s; }
    server { listen 3307; proxy_pass mysql_backend; proxy_connect_timeout 30s; }
    server { listen 5437; proxy_pass pg_backend; proxy_connect_timeout 30s; }
    server { listen 33891; proxy_pass rdp_backend; proxy_connect_timeout 30s; }
}
```

### Makefile 补充

```makefile
# ===== 部署 =====
.PHONY: deploy-lite deploy-full deploy-down deploy-logs

deploy-lite:
	PROFILE=lite docker compose -f deployments/docker-compose.yaml --profile lite up -d --build

deploy-full:
	PROFILE=full docker compose -f deployments/docker-compose.yaml --profile full up -d --build

deploy-down:
	docker compose -f deployments/docker-compose.yaml down

deploy-logs:
	docker compose -f deployments/docker-compose.yaml logs -f

deploy-migrate:
	docker compose -f deployments/docker-compose.yaml exec api-server turjmp --config /etc/turjmp/config.yaml --migrate up

# ===== 构建 =====
build:
	go build -ldflags="-s -w" -o bin/turjmp ./cmd/turjmp
```

---

## 实现顺序总览

```
后端 Phase B1 (基础设施)  ████████░░░░░░░░░░░░░░░░  2-3 周
  ├── 项目脚手架
  ├── 数据库 + 迁移
  ├── 用户认证 (JWT + MFA)
  ├── RBAC (Casbin)
  ├── 资产管理
  ├── Connection Token 系统
  ├── 系统配置引擎 (DB 驱动)
  └── 生产基础设施 (健康检查/限流/优雅关闭)

后端 Phase B2 (SSH 代理) ░░░░░░░░████████░░░░░░░░  2-3 周
  ├── SSH daemon
  ├── SSH 转发 + 跳板机
  ├── SSH 会话录制 (asciicast)
  ├── WebSocket 终端桥接
  └── 命令过滤 ACL

后端 Phase B3 (DB 代理)  ░░░░░░░░░░░░░░░░████████░░  2 周
  ├── MySQL 协议代理
  ├── PostgreSQL 协议代理
  ├── WebSocket DB 终端 (usql)
  └── SQL 审计日志

后端 Phase B4 (RDP 代理)  ░░░░░░░░░░░░░░░░░░░░████  1-2 周
  ├── guacd 集成
  ├── RDP WebSocket 桥接
  └── RDP 会话录制

后端 Phase B5 (原生透传)  ░░░░░░░░░░░░░░░░░░░░░░███  1-2 周
  ├── MySQL/PG TCP 透明代理 (Magnus)
  ├── RDP TCP 透明代理 (Razor)
  └── SDK 连接文件生成

═══════════════════════ 后端完成 ══════════════════════

前端 Phase F1 (管理控制台) ██████████████████████████  2-3 周
  ├── 项目脚手架
  ├── 登录 + MFA 页面
  ├── 资产管理页面
  ├── 用户权限管理
  └── 仪表盘 + 审计 + 系统配置

前端 Phase F2 (Web 终端)   ░░░░░░░░░░░░░░░░░░░░░░░░  1-2 周
  ├── xterm.js 终端
  ├── DB Web 终端
  └── 快速连接入口

前端 Phase F3 (RDP + 原生) ░░░░░░░░░░░░░░░░░░░░░░░░  1 周
  ├── 会话回放 (asciinema-player)
  ├── RDP Web 客户端
  └── 原生客户端连接入口

═══════════════════════ 全部完成 ══════════════════════
```

**预计总工期: 12-18 周**（依团队规模和并行程度而定）

---

## 关键架构决策 (ADR)

| # | 决策 | 理由 |
|---|------|------|
| ADR-1 | **单二进制多角色** | 一个 `turjmp` 二进制通过 `--api/--ssh-proxy/--db-proxy/--rdp-proxy` 启用角色，部署仍可按角色独立扩容，开发和镜像构建更简单 |
| ADR-2 | **配置分层: 文件引导 + 数据库驱动** | `config.yaml` 仅含启动必需的 DB 连接/端口/密钥路径；其余全部存入 `settings` 表由前端管理，修改即时生效无需重启 |
| ADR-3 | **RS256 JWT 非对称签名** | API server 签发，代理层公钥验证，无需共享密钥，无需 Redis 查验证 |
| ADR-4 | **Asciicast v2 会话录制** | CLI + Web 双回放，流式写入，高压缩比，JumpServer 同方案 |
| ADR-5 | **Connection Token 中央授权** | 所有连接无论 Web 还是原生客户端都通过 token 统一鉴权，可审计可撤销 |
| ADR-6 | **usql 子进程做 DB CLI** | 避免为每种数据库写 CLI 前端，usql 统一支持 MySQL/PG/Oracle/SQL Server |
| ADR-7 | **guacd sidecar 处理 RDP** | Go 无生产级 RDP 库，guacd (Apache 项目) 是唯一成熟方案 |
| ADR-8 | **sqlx (管理) + pgx (录像) 多驱动** | sqlx 手写 SQL 精确控制；SQLite 轻量部署，pgx 生产高吞吐 |
| ADR-9 | **SQLite + PostgreSQL 双后端** | 通过配置切换驱动，goose SQL 迁移统一管理，满足从单文件部署到集群的全场景 |
| ADR-10 | **StorageBackend 接口抽象录像存储** | 本地/S3/MinIO/OSS 统一接口，流式上传，签名 URL 回放，配置一键切换 |
| ADR-11 | **go-mysql/pgproto3 而非通用 TCP 代理** | 协议感知代理才能做 SQL 审计和脱敏，纯 TCP 中继无法解析查询 |
