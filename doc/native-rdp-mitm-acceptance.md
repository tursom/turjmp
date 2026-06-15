# Native RDP MITM Acceptance Checklist

Use this checklist for the manual Windows `mstsc` acceptance pass. Record command output, timestamps, and session IDs, but never record RDP proxy passwords or target Windows passwords.

## Test Environment

- Turjmp image/tag:
- FreeRDP version build arg:
- Native RDP public host:
- Native RDP public port:
- Windows client version:
- Target Windows host:
- Test Turjmp user:
- Target asset ID:
- Target account ID:

## Happy Path

1. Start Turjmp with `deployments/docker-compose.yaml` plus `deployments/docker-compose.native-rdp.yaml`.
2. Confirm `GET /health/ready` returns `status=ready` and `components.native_rdp.status=ready`.
3. Log in to Turjmp as the test user.
4. Set or reset the user's independent RDP proxy password.
5. Open a Windows asset that has RDP protocol enabled and an active password account.
6. Download the native `.rdp` file.
7. Open the file with Windows `mstsc`.
8. Enter the Turjmp RDP proxy route username from the file and the independent RDP proxy password.
9. Confirm the Windows desktop opens without exposing the managed target password to the user.
10. Disconnect the session cleanly.
11. Confirm the Turjmp session list shows protocol `rdp`, login source `rdp_client`, and a finished timestamp.

Evidence to record:

- `/health/ready` response with secrets absent.
- downloaded `.rdp` file content with no password.
- session ID and finished timestamp.
- audit entries for start and finish.

## Failure Modes

### Wrong RDP Proxy Password

1. Download a valid `.rdp` file.
2. Open it in `mstsc`.
3. Enter the route username and an incorrect RDP proxy password.
4. Confirm the client receives a generic authentication failure.
5. Confirm audit reason `front_auth_failed`.

### Revoked Permission

1. Remove the user's `connect` permission for the target asset/account.
2. Reuse or redownload the `.rdp` file.
3. Confirm new native RDP connection attempts fail.
4. Confirm audit reason `missing_connect_permission`.

### Target Password Wrong

1. Change the managed target account password in Turjmp to an incorrect value.
2. Connect with a valid RDP proxy password.
3. Confirm target login fails.
4. Confirm the native session is finished and audit/session reason indicates `target_login_failed`.

### Target Host Down

1. Stop or firewall the target Windows RDP endpoint.
2. Connect with valid Turjmp-side credentials.
3. Confirm connection fails.
4. Confirm audit/session reason indicates `target_connect_failed`, `target_dial_failed`, or equivalent target unreachable state.

### Max Connections Exceeded

1. Set `proxy.rdp.max_connections` to a low value for the test.
2. Open native RDP sessions until the limit is reached.
3. Attempt one additional connection.
4. Confirm the extra attempt is denied.
5. Confirm audit reason `max_connections`.

## Rollback Acceptance

1. Restart without `deployments/docker-compose.native-rdp.yaml` or set `proxy.rdp.native_enabled=false`.
2. Confirm `components.native_rdp.status=disabled`.
3. Confirm host port `33890` is no longer exposed.
4. Confirm Web RDP through `/ws/rdp/?token=...` still works.
