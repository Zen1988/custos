# Console broker and clustered deployment

## Reboot and green status

Green means the hypervisor reports powered-on. It is a prerequisite for guest reboot,
not evidence that a reboot finished: a guest can reboot while hypervisor power stays
green. The worker checks current power and guest-tools readiness before requesting
reboot. Its lock stays until verified/reconciled guest completion, as before.

## Console implementation

The workspace Open console action requires View and Console permission, healthy
backend and a powered-on mapped VM. It acquires the same cross-user VM operation
lock: console and power/snapshot operations are exclusive under the current policy.
The browser receives only an opaque Custos console-session ID, not provider tickets,
JWTs, passwords, cookies or management URLs.

An ASGI WebSocket broker validates the signed login cookie, server-side login-session
record, exact browser Origin, one-use console authorization, VM mapping and RBAC.
It acquires a provider ticket server-side and proxies the binary console stream.
Tickets are never persisted in browser sessions or logs. Console requests expire
after 30 seconds if unused; connected sessions last at most ten minutes. Reconnect
requires a fresh authorization. Access is rechecked and a shared heartbeat updated
every five seconds. Logout revokes the DB login session; permission revocation or
logout closes the console. Broker loss leaves a lock until its 60-second heartbeat
timeout is cleaned up by the worker. Connected sockets do not migrate between pods.

Console issue/connect/close/denied/expiry events are audited and forwarded to syslog.
This is session auditing, not keystroke/video recording. Recording inside the guest
requires a dedicated recording layer/CyberArk integration. Console input can contain
guest passwords and is deliberately not copied into general audit logs.

### Runtime configuration

Install `.venv\Scripts\python -m pip install -e '.[postgres,console]'`, initialize the
new `auth_sessions`/`console_sessions` tables, and run:

```powershell
$env:CUSTOS_PUBLIC_ORIGIN = 'https://custos.example.com'
$env:CUSTOS_CONSOLE_ALLOWED_HOSTS = 'esxi01.example.com,esxi02.example.com,pc.example.com'
$env:CUSTOS_CONSOLE_CA_BUNDLE = 'C:\certificates\management-ca.pem'
.\.venv\Scripts\python -m uvicorn custos.console_gateway:create_gateway --factory --host 127.0.0.1 --port 8080 --no-access-log
```

Use a TLS reverse proxy supporting WebSocket upgrades and connection timeouts over
ten minutes. Route HTTP and WebSockets to the ASGI service on the same public origin.
Allow only approved ESXi/Prism console destinations in both the hostname allowlist
and deployment egress policy. Certificates/hostnames must validate; the broker never
disables TLS verification. ESXi console certificates need a trusted issuing CA,
even when the vCenter certificate itself was approved during setup.

### VMware browser client dependency

The server acquires an `AcquireTicket('webmks')` ticket after verifying vCenter/VM
identity and power state. The browser needs the VMware **HTML Console SDK/WebMKS**.
Its licensed files are not redistributed here. Obtain them through your VMware
entitlement/approved SDK download and place these under
`CUSTOS_WEBMKS_ASSET_DIR` (default `web/static/vendor/webmks`):

- `wmks.min.js`, `wmks-all.css` and accompanying SDK assets.
- Compatible `jquery.min.js` and `jquery-ui.min.js` under those names.

If assets/configuration are missing, console launch returns a clear unavailable
response; it does not expose a direct hypervisor link as a fallback. Full VMware
console rendering cannot be validated until those files and a live backend are
available. Broadcom lists this as the final HTML Console SDK release, compatible
with vSphere 7.0 and later; validate the intended vCenter/ESXi versions.

### Nutanix version dependency

Official Nutanix guidance places the supported console-token API under VMM **v4.2+**,
although its example uses a v4.0 URL. The existing v4.0 inventory/power integration
therefore does not prove console availability. The console adapter defaults to v4.2;
set `CUSTOS_NUTANIX_CONSOLE_API_VERSION=v4.0` only if your deployment exposes that
documented console action. Unsupported endpoints fail explicitly.

The flow generates a token, polls its task, and accepts only the documented
`WsUri`/`VmConsoleToken` result with the expected VM-specific route. Prism must also
issue the supported session cookie required for the WebSocket handshake; if the
configured API authentication does not issue it, console acquisition fails rather
than inventing an undocumented authentication bypass. These response/authentication
details require live acceptance against the deployed release.

The noVNC 1.6.0 browser client is included from the official release, with license
notices and a source hash manifest. `scripts/install_novnc.py` reproduces the import
and detects a changed release-archive hash on a repeated run. Nutanix consoles use
the VNC client; VMware uses its vendor WebMKS client.

## Clustering

SQLite is a single-host development database, not Custos's multi-node deployment
store. Set `CUSTOS_CLUSTER_MODE=true`: startup rejects SQLite for both inventory and
RBAC. Use separate PostgreSQL databases and separate inventory/RBAC reader/writer
identities, ideally behind managed HA endpoints. This application does not create
or administer PostgreSQL replication/failover itself.

All web/gateway replicas share database endpoints, session-signing key, backend key,
RBAC key and client assets. The RBAC key remains different from the backend key.
Workers get the RBAC reader URL, never the admin writer URL. No SQLite file is placed
on a shared volume. Signed sessions and durable login/console rows allow any web
replica to handle subsequent requests; WebSocket connections remain on their chosen
replica until closed. No sticky sessions are needed for the next fresh connection.

PostgreSQL advisory locking elects one worker leader per processing cycle. Other
worker replicas stay idle and can take over after leader loss. This is active/passive
job processing, not parallel mutation workers. Per-VM primary-key locks and
idempotency constraints still protect individual operations. Only a leader may mark
interrupted executing work unknown; a newly started follower cannot invalidate a
live leader's operation. Commands with ambiguous outcomes are never replayed.

`Dockerfile` builds the ASGI runtime; `deployments/kubernetes/custos.yaml` supplies
two web and two worker replicas as a deployment template. Build/publish your image,
replace the image placeholder, mount licensed/CA assets and configure TLS ingress,
egress policy and these pre-existing Kubernetes Secrets:

- `custos-runtime`: inventory/RBAC-reader URLs, shared signing/backend/RBAC keys,
  public origin, console hostname allowlist and any syslog/CA settings.
- `custos-rbac-admin`: RBAC writer URL, supplied only to admin-capable web pods.

Initialize schema once using a deployment/migration identity before replicas start.
Current bootstrap is create-missing-tables, not an automated migration framework.
Health probes, disruption budgets, secret mounting paths, production ingress and
database HA provisioning need environment-specific deployment configuration.
PostgreSQL multi-node failover and live console rendering have not been exercised
in this workspace; passing local tests is not a claim of production HA validation.

Sources: [SQLite deployment guidance](https://www.sqlite.org/whentouse.html),
[VMware HTML Console SDK](https://developer.broadcom.com/sdks/vmware-html-console-sdk/latest/),
[Nutanix public console API](https://www.nutanix.dev/2026/05/01/vm-console-external-access/),
[official noVNC release](https://github.com/novnc/noVNC/releases/tag/v1.6.0).
