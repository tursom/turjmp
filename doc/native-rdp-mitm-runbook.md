# Native RDP MITM Runbook

This runbook covers the Phase F3R native RDP MITM path. Web RDP through guacd remains available on the existing WebSocket proxy and is the rollback path.

## Build And Runtime Requirements

- The Docker image builds FreeRDP from source with proxy app support and installs `freerdp-proxy` in `/opt/freerdp/bin/freerdp-proxy`.
- The image also builds and installs the Turjmp FreeRDP proxy plugin from `native/rdp-freerdp-plugin`.
- The native RDP proxy is disabled by default. It starts only when `proxy.rdp.native_enabled=true`.
- Required files when native RDP is enabled:
  - `/keys/rdp-native.crt`
  - `/keys/rdp-native.key`
  - writable work dir `/var/lib/turjmp/rdp-native`

## Enable Native RDP In Docker

Generate or install the native RDP certificate and key:

```sh
mkdir -p deployments/keys deployments/rdp-native
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout deployments/keys/rdp-native.key \
  -out deployments/keys/rdp-native.crt \
  -days 365 \
  -subj "/CN=turjmp-rdp"
chmod 600 deployments/keys/rdp-native.key
```

Start with the explicit native RDP override:

```sh
docker compose -f deployments/docker-compose.yaml -f deployments/docker-compose.native-rdp.yaml up -d --build
```

Optional environment variables:

- `TURJMP_RDP_NATIVE_PORT`: host port mapped to container `33890`.
- `TURJMP_RDP_NATIVE_PUBLIC_HOST`: host name written into downloaded `.rdp` files.
- `TURJMP_RDP_NATIVE_PUBLIC_PORT`: public port written into downloaded `.rdp` files.
- `FREERDP_VERSION`: FreeRDP source tag used at image build time.

## Disable Or Roll Back

Stop native RDP exposure by removing the override file from the compose command:

```sh
docker compose -f deployments/docker-compose.yaml up -d
```

Equivalent config rollback is setting:

```yaml
proxy:
  rdp:
    native_enabled: false
```

Leave Web RDP unchanged: keep `proxy.rdp.addr` on `33891`, keep guacd running, and keep `/ws/rdp/?token=...` traffic routed as before.

## Rotate Native RDP Certificate

1. Write the replacement cert/key to temporary names under `deployments/keys`.
2. Set key permissions to `0600`.
3. Replace `rdp-native.crt` and `rdp-native.key` atomically during a maintenance window.
4. Restart Turjmp so `freerdp-proxy` loads the new certificate.
5. Check `/health/ready` and the RDP proxy `/health`.

## Reset RDP Proxy Passwords

Users can reset their own independent RDP proxy password from the security page. Administrators can manage a user's RDP proxy credential through the user management credential API/UI. This password is separate from the Web login password and is the password entered into `mstsc`.

Do not paste RDP proxy passwords or target Windows passwords into logs, tickets, or acceptance evidence.

## Health Checks

API readiness:

```sh
curl -s http://127.0.0.1:8085/health/ready
```

RDP proxy readiness from inside the container network:

```sh
curl -s http://127.0.0.1:33891/health
```

Expected native statuses:

- `disabled`: native RDP is intentionally off.
- `ready`: native RDP is enabled, config dependencies exist, and the engine process is running.
- `not_ready`: native RDP is enabled but the engine, cert/key, work dir, or process state is invalid.

## Common mstsc Failures

- Wrong RDP proxy password: `mstsc` shows a generic authentication failure; server audit action is `rdp.native.denied` with reason `front_auth_failed`.
- Permission revoked: new native RDP sessions are denied with reason `missing_connect_permission`.
- Target password wrong: native session may start, then finish with reason `target_login_failed`.
- Target host down or blocked: native session may finish with reason `target_connect_failed` or `target_dial_failed`.
- Max connections exceeded: native session start is denied with reason `max_connections`.
- Certificate warning: expected when using a self-signed cert; install a trusted cert if operators require a clean client prompt.

## Logs And Secret Handling

Acceptable logs contain session IDs, asset IDs, account IDs, denial reasons, and generic engine error classes. Logs must not contain:

- RDP proxy password
- target Windows password
- generated FreeRDP config content
- `ProxyAuth` value
- private key content
