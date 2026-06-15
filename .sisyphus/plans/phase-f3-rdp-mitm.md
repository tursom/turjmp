# Phase F3 RDP MITM: staged implementation plan

## Context

- Goal: native Windows `mstsc` connects to Turjmp, while Turjmp uses the managed target Windows account password to connect onward to the real RDP server.
- Chosen path: RDP MITM proxy, not RD Gateway, not connector, not Web RDP as the main native path.
- First target reachability mode: Turjmp RDP proxy directly dials the target asset RDP endpoint.
- Front-side authentication: long-lived RDP proxy account password, independent from the existing Web login password.
- Current implementation truth: RDP is currently WebSocket + guacd fallback through `/ws/rdp/?token=...`; SDK RDP currently returns `web_rdp`/`.url`, not a real `.rdp` file.

## Scope Rules

- Do not hand-roll a full RDP/CredSSP protocol stack in Go.
- Use FreeRDP proxy/server capability, or an equivalent mature RDP MITM engine, for RDP front/back protocol termination.
- Keep Web RDP/guacd working as a separate browser and recording path.
- Do not implement connector, RD Gateway, UDP multitransport, RemoteApp, smartcard, target-side MFA, or screen recording in this phase.
- First version supports Windows `mstsc` only.
- First version supports target asset accounts with `secret_type=password` only.

## Dependency Graph

```text
Wave 1: F3R.1 (contracts + credentials) ───── no deps
Wave 2: F3R.2 (RDP engine PoC wrapper) ────── depends F3R.1 contracts
Wave 3: F3R.3 (auth + routing) ────────────── depends F3R.1 + F3R.2 wrapper
Wave 4: F3R.4 (session lifecycle) ─────────── depends F3R.3
Wave 5: F3R.5 (frontend native entry) ─────── depends F3R.1 + F3R.3 API shape
Wave 6: F3R.6 (hardening + acceptance) ────── depends F3R.2-F3R.5
```

Each wave is intended to be one reviewable commit with similar task volume: one bounded backend slice, matching tests, and at most one frontend surface where applicable.

## Tasks

### Wave 1: F3R.1 - Contracts, config, and RDP proxy credentials

- Add the persisted model for user-level RDP proxy credentials, separate from `users.password_hash`.
- Add service APIs for setting, resetting, disabling, and checking RDP proxy credential status.
- Add RBAC/access-map keys for the new credential endpoints.
- Extend RDP proxy config with native MITM listen address, public host/port, certificate/key paths, and feature toggle.
- Define the route username format used by `mstsc`, for example `<turjmp_username>#<asset_id>#<account_id>`.
- Add backend tests for credential lifecycle, inactive users, disabled credentials, and route username parsing.
- QA: migrations run for SQLite and Postgres; `go test ./internal/service ./internal/api` passes.

### Wave 2: F3R.2 - RDP MITM engine PoC and Go wrapper boundary

- Add an internal wrapper around the selected RDP MITM engine rather than spreading C/CLI calls through business code.
- Prove the engine can accept a Windows `mstsc` connection and connect onward to a fixed Windows RDP target using supplied target username/password.
- Make startup fail fast when the native RDP proxy is enabled but the engine binary/library or cert/key material is missing.
- Capture structured engine events needed by Turjmp: connection started, authenticated, target dial failed, target login failed, disconnected.
- Add tests around wrapper config rendering, secret redaction, process lifecycle, and error classification.
- QA: a local PoC command documents the exact FreeRDP build/runtime requirements; `go test ./internal/proxy/rdp` passes without a real Windows target.

#### F3R.2 FreeRDP CLI PoC notes

- Selected engine: FreeRDP proxy CLI, invoked as `freerdp-proxy <generated-config.ini>`.
- Build/runtime requirement: FreeRDP must be built or packaged with proxy application support enabled (`WITH_PROXY_APP=ON`) so the `freerdp-proxy` binary is available on `PATH`, or set `proxy.rdp.native_engine_path` to its absolute path.
- Turjmp renders a fixed-target INI containing `[Server] Host/Port`, `[Target] FixedTarget/Host/Port/User/Password`, `[Security]`, and `[Certificates] CertificateFile/PrivateKeyFile`.
- Certificate material is supplied by `proxy.rdp.native_cert_path` and `proxy.rdp.native_key_path`; temporary generated config is written under `proxy.rdp.native_work_dir`.
- Manual PoC shape:
  - Configure `proxy.rdp.native_enabled=true`, `proxy.rdp.native_addr=":33890"`, valid cert/key paths, and a writable native work dir.
  - Start Turjmp RDP proxy role so startup validates the FreeRDP binary and certificate material.
  - Run the wrapper with a fixed Windows target account; connect `mstsc` to the native listen address and authenticate against the FreeRDP front side.
- Stage boundary: the fixed target is only for Wave 2 engine verification. Wave 3 adds Turjmp front-side authentication, authorization, target/account resolution, and managed-password handoff.

### Wave 3: F3R.3 - Front-side auth, authorization, and target resolution

- Implement `mstsc` front-side authentication against the independent RDP proxy credential.
- Resolve `<turjmp_username>#<asset_id>#<account_id>` to user, asset, account, platform protocol port, and decrypted target password.
- Enforce existing `connect` permission, active user, active asset, active account, and `secret_type=password`.
- Pass only the resolved target host, port, target username, and target password to the MITM engine.
- Return precise denial reasons in logs while keeping `mstsc` errors generic.
- Add tests for bad password, malformed route username, missing permission, inactive records, wrong protocol, missing RDP platform port, and non-password target account.
- QA: `go test ./internal/service ./internal/proxy/rdp ./internal/api` passes.

### Wave 4: F3R.4 - Session lifecycle, limits, and audit integration

- Create Turjmp `sessions` rows when native RDP MITM auth and target resolution succeed.
- Mark sessions finished on disconnect, target connection failure after session creation, proxy shutdown, and idle timeout.
- Set `protocol=rdp`, `type=rdp`, and `login_from=rdp_client` for native MITM sessions.
- Reuse RDP max connection and idle timeout settings, or add explicit native-RDP settings if the existing keys are too Web-RDP-specific.
- Record audit logs for credential changes, native RDP connection attempts, denied attempts, and session completion.
- Ensure target password and RDP proxy password material never appears in logs, audit details, command args, or process listings.
- Add tests for session create/finish idempotency, limiter behavior, timeout path, and redaction.
- QA: native RDP sessions appear in session list/detail and do not break existing Web RDP session recording paths.

### Wave 5: F3R.5 - Frontend settings and `.rdp` download entry

- Add a personal security UI for setting/resetting/disabling the independent RDP proxy password.
- Extend `NativeConnectionPanel` to include `rdp` when the asset platform exposes the RDP protocol.
- Change SDK RDP output from `web_rdp`/`.url` fallback to a real `.rdp` file for the native MITM path.
- The `.rdp` file must include proxy host/port and route username, but must not include target Windows password or RDP proxy password.
- In asset detail, show clear disabled states when the current user has no RDP proxy password, the asset/account is inactive, or the protocol is not RDP-capable.
- Keep SSH/MySQL/Postgres native connection behavior unchanged.
- Add frontend type/API updates and static checks for the new RDP credential status and SDK response shape.
- QA: `npm run test` in `web/` passes; downloaded `.rdp` opens in mstsc and targets the native RDP proxy endpoint.

### Wave 6: F3R.6 - End-to-end acceptance, packaging, and rollback safety

- Add deployment/package requirements for the selected RDP MITM engine and native RDP proxy cert/key material.
- Update Docker/dev config so the native RDP proxy can be enabled explicitly without changing Web RDP/guacd defaults.
- Add health/readiness behavior that distinguishes API, Web RDP, and native RDP MITM readiness.
- Run an end-to-end Windows test: set RDP proxy password, download `.rdp`, open in mstsc, proxy logs in to target Windows using the managed asset password, then session finishes cleanly.
- Add failure-mode acceptance cases: wrong RDP proxy password, revoked permission, target password wrong, target host down, max connections exceeded.
- Document operator runbook: enabling/disabling native RDP MITM, rotating certs, resetting RDP proxy passwords, and diagnosing common mstsc failures.
- QA: `go test ./...`, `npm run test`, and the manual mstsc acceptance checklist pass before marking Phase F3R complete.

## Public API and UI changes

- Add authenticated API endpoints for current-user RDP proxy credential status and updates.
- Extend or replace `POST /api/v1/authentication/connection-tokens/sdk-url` RDP behavior so `protocol=rdp` returns native MITM `.rdp` content when native RDP is enabled.
- Add access-map/RBAC entries for the RDP proxy credential endpoints.
- Add frontend settings UI for RDP proxy password management.
- Add RDP native connection support to the asset detail native connection panel.

## Acceptance Criteria

- A user with `connect` permission can set an RDP proxy password, download a `.rdp` file, open it with Windows `mstsc`, authenticate to Turjmp, and reach the Windows desktop without knowing the target Windows password.
- Turjmp uses the selected asset account's managed password for the target RDP login.
- Revoking permission or disabling the asset/account blocks new native RDP sessions.
- No managed target password or RDP proxy password is exposed through API responses, logs, audit logs, frontend state, downloaded files, or command-line arguments.
- Existing SSH/MySQL/Postgres SDK flows and existing Web RDP/guacd behavior still pass their current tests.

## Explicit non-goals for this plan

- Connector or reverse tunnel access to customer networks.
- RD Gateway compatibility.
- Native RDP screen recording.
- macOS/iOS/Android RDP client compatibility.
- Passwordless SSO to the target Windows host.
- Kerberos delegation, smartcard, RemoteApp, UDP multitransport, printer/drive redirection policy controls.
