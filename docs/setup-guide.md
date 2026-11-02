# Custos setup guide

Step-by-step reference installation • Ubuntu Server 24.04 LTS • PostgreSQL • nginx or Apache • Last updated 2 November 2026.

Use this file before the application is running. After installation, Custos admins can open **Setup guide** at `/admin/setup-guide`. Commands below are installation examples, not commands Custos runs automatically. Replace example hostnames, certificate paths and password placeholders before use.

[TOC]

## 1. Choose the deployment

| Deployment | Components | Use |
|---|---|---|
| Development | One app, one worker, two separate SQLite files | Local development only; no clustering |
| Pilot | Linux app host, PostgreSQL inventory/RBAC databases, HTTPS proxy, app and worker services | Start here for live acceptance on disposable VMs |
| Cluster | Two or more app/gateway replicas, two worker replicas, shared PostgreSQL HA endpoints, load balancer | Intended HA topology; requires environment-specific failover acceptance |

Recommended starting point for a small pilot: **2 vCPU, 4 GB RAM, 20 GB app disk**, plus database/audit capacity on the database host. This is an initial sizing estimate, not a measured capacity guarantee. Console concurrency, inventory size and audit retention determine real sizing. Keep guest-network traffic separate from management-plane traffic.

Custos provides application coordination; it does not install PostgreSQL replication or promote database standbys. Use your managed PostgreSQL HA service or an established PostgreSQL HA deployment.

## 2. Prerequisites and supported systems

| Component | Current target / requirement |
|---|---|
| Application OS | Ubuntu Server 24.04 LTS is this guide's reference. Other Linux distributions need equivalent packages/service configuration; they are not certified here |
| Python | Python 3.11 or later; the reference Ubuntu installation uses Python 3.12 |
| Database | PostgreSQL 16 is a practical Ubuntu 24.04 baseline. PostgreSQL is required for cluster mode; actual HA acceptance remains pending |
| Reverse proxy | nginx with WebSocket support, or Apache HTTP Server 2.4.47+ with reverse proxy/WebSocket support |
| VMware | vCenter 8.0 U3 or 9.x; dedicated scoped service identity; VMware Tools for graceful guest operations |
| Nutanix | Prism Central managing AHV, stable v4.0 inventory/power/recovery APIs; NGT for graceful operations |
| VMware console | Licensed WebMKS/HTML Console SDK assets and trusted ESXi console certificates |
| Nutanix console | Supported console-token API; official guidance places it under v4.2+. Inventory v4.0 support does not prove console support |
| Identity | Local accounts and scoped AD/LDAP imports/login. Generic LDAP currently expects inetOrgPerson, entryUUID and groupOfNames/member |
| Browser | A modern desktop browser with JavaScript, secure cookies and WebSockets; validate your PSM-hosted browser too |
| Certificates | Public Custos HTTPS certificate, PostgreSQL TLS certificate/CA, directory CA and management-console CA as applicable |

These are implementation targets, not a claim that every OS/hypervisor combination has passed live certification. Windows has been used for local development; this guide does not define a Windows production service deployment.

Prepare a dedicated VM folder/scope and disposable test VMs. For VMware, the service identity needs System.View, System.Read, VirtualMachine.Interact.ConsoleInteract, PowerOn, PowerOff, Reset and VirtualMachine.State.CreateSnapshot on the managed VMs. Nutanix needs scoped VM read/operator, console-token and recovery-point read/create permissions as applicable. Do not use a global administrator account as the normal backend identity.

### Network checklist

| Connection | Typical destination port |
|---|---|
| User / PSM browser → Custos proxy | TCP 443 |
| Proxy → local ASGI service | TCP 8080 on loopback; restrict remote app ports to trusted proxies in a cluster |
| App / worker → PostgreSQL | TCP 5432 with certificate verification |
| App / worker → vCenter and approved ESXi console hosts | TCP 443, or explicitly configured management ports |
| App / worker → Prism Central | TCP 9440, or configured port |
| App / directory sync → AD/LDAP | TCP 636 LDAPS, or TCP 389 with required StartTLS |
| App / worker → approved DNS resolvers | UDP/TCP 53 |
| Worker → external syslog | TCP 6514 TLS recommended; TCP/UDP 514 only when explicitly selected |

Users need no direct route to vCenter, ESXi or Prism. Configure correct forward/reverse DNS and time synchronization. Backend integration credentials and console tickets remain server-side.

## 3. Install Linux packages and application files

The PostgreSQL packages below install a **single database instance for a pilot**. For an existing managed/HA database, install only the client on the app host and provision the databases there instead.

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip ca-certificates openssl postgresql postgresql-client
sudo systemctl enable --now postgresql
sudo useradd --system --home /opt/custos --shell /usr/sbin/nologin custos
sudo install -d -o "$USER" -g "$USER" /opt/custos
git clone https://github.com/Zen1988/custos.git /opt/custos
cd /opt/custos
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install '.[postgres,console]'
sudo chown -R root:root /opt/custos
sudo install -d -m 0755 /etc/custos /etc/custos/ca
```

If the service account or installation directory already exists, reuse it deliberately rather than rerunning the account/clone commands. Install a reviewed release/commit for deployment, and ensure it includes the features described by this guide. The local workspace may contain changes that have not yet been published to GitHub.

The official noVNC client is included in the source tree. VMware's licensed client is a separate prerequisite; see step 10.

## 4. Create separate PostgreSQL databases and identities

This example uses two databases on one PostgreSQL server with independent owners and logins. A separate RBAC PostgreSQL server is also supported. Do not give the inventory login access to the RBAC database.

Run the PostgreSQL administrator commands on the **database host** (or use your managed database's administration connection). The app-host commands in later sections connect to that same server through its certificate-matching DNS name. Use `\password` to enter passwords interactively; do not put real passwords into shell history or checked-in SQL.

```bash
sudo -u postgres psql
```

```sql
CREATE ROLE custos_inventory_bootstrap LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE custos_inventory LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE custos_rbac_bootstrap LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE custos_rbac_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE custos_rbac_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
\password custos_inventory_bootstrap
\password custos_inventory
\password custos_rbac_bootstrap
\password custos_rbac_reader
\password custos_rbac_writer
CREATE DATABASE custos_inventory OWNER custos_inventory_bootstrap;
CREATE DATABASE custos_rbac OWNER custos_rbac_bootstrap;
REVOKE ALL ON DATABASE custos_inventory FROM PUBLIC;
REVOKE ALL ON DATABASE custos_rbac FROM PUBLIC;
GRANT CONNECT ON DATABASE custos_inventory TO custos_inventory, custos_inventory_bootstrap;
GRANT CONNECT ON DATABASE custos_rbac TO custos_rbac_reader, custos_rbac_writer, custos_rbac_bootstrap;
\connect custos_inventory
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO custos_inventory;
\connect custos_rbac
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO custos_rbac_reader, custos_rbac_writer;
\quit
```

Configure PostgreSQL TLS before the app connects. Obtain a server certificate whose SAN matches the **database hostname** used in the URLs, protect its private key, and install the issuing CA at `/etc/custos/ca/postgres-ca.pem` on app/worker hosts. Configure `ssl`, `ssl_cert_file`, `ssl_key_file`, `listen_addresses` and tightly scoped `hostssl` entries in PostgreSQL's configuration/`pg_hba.conf`. Use SCRAM authentication. Find the actual configuration paths with `SHOW config_file;` and `SHOW hba_file;` in psql. Restrict port 5432 to the app/worker/admin hosts. A packaged self-signed certificate is not automatically a certificate trusted for your chosen DNS name.

Check connectivity before proceeding:

```bash
psql 'host=db.example.com dbname=custos_inventory user=custos_inventory_bootstrap sslmode=verify-full sslrootcert=/etc/custos/ca/postgres-ca.pem' -W -c 'SELECT current_database(), current_user;'
```

See the official [Ubuntu PostgreSQL installation guide](https://www.postgresql.org/download/linux/ubuntu/), [Ubuntu configuration guide](https://ubuntu.com/server/docs/how-to/databases/install-postgresql/) and [PostgreSQL privileges](https://www.postgresql.org/docs/16/ddl-priv.html).

## 5. Configure secrets and environment

Create three independent keys once. Back them up in a secret manager separately from database backups. Use the **same corresponding keys on every replica**; never generate new keys when a service restarts.

```bash
sudo /opt/custos/.venv/bin/python - <<'PY'
from pathlib import Path
from cryptography.fernet import Fernet
import os, secrets
p = Path('/etc/custos/keys.env')
if p.exists():
    raise SystemExit('keys.env already exists; refusing to replace encryption keys')
p.write_text('CUSTOS_SESSION_SECRET=' + secrets.token_urlsafe(48) + '\n'
    + 'CUSTOS_ENCRYPTION_KEY=' + Fernet.generate_key().decode() + '\n'
    + 'CUSTOS_RBAC_KEY=' + Fernet.generate_key().decode() + '\n')
os.chmod(p, 0o600)
PY
sudo touch /etc/custos/runtime.env /etc/custos/admin.env /etc/custos/bootstrap.env
sudo chmod 0600 /etc/custos/*.env
```

Edit the following files with `sudoedit`. Replace `URL_ENCODED_PASSWORD` separately for each login. Passwords containing reserved URL characters must be URL-encoded. Do not print these environment files in diagnostics.

`/etc/custos/runtime.env` — both app and worker:

```ini
CUSTOS_DATABASE_URL='postgresql+psycopg://custos_inventory:URL_ENCODED_PASSWORD@db.example.com:5432/custos_inventory?sslmode=verify-full&sslrootcert=/etc/custos/ca/postgres-ca.pem'
CUSTOS_RBAC_DATABASE_URL='postgresql+psycopg://custos_rbac_reader:URL_ENCODED_PASSWORD@db.example.com:5432/custos_rbac?sslmode=verify-full&sslrootcert=/etc/custos/ca/postgres-ca.pem'
CUSTOS_CLUSTER_MODE=true
CUSTOS_PUBLIC_ORIGIN=https://custos.example.com
CUSTOS_CONSOLE_ALLOWED_HOSTS=esxi01.example.com,esxi02.example.com,pc.example.com
CUSTOS_CONSOLE_CA_BUNDLE=/etc/custos/ca/management-ca.pem
CUSTOS_SYSLOG_HOST=logs.example.com
CUSTOS_SYSLOG_TRANSPORT=tls
CUSTOS_SYSLOG_PORT=6514
CUSTOS_SYSLOG_CA_BUNDLE=/etc/custos/ca/logging-ca.pem
```

Omit console CA/allowlist or syslog settings that are not yet configured; do not leave nonexistent CA paths. HTTPS login works without console assets, but console launch will remain unavailable. An omitted syslog host leaves events queued locally.

`/etc/custos/admin.env` — admin-capable web service only:

```ini
CUSTOS_RBAC_ADMIN_DATABASE_URL='postgresql+psycopg://custos_rbac_writer:URL_ENCODED_PASSWORD@db.example.com:5432/custos_rbac?sslmode=verify-full&sslrootcert=/etc/custos/ca/postgres-ca.pem'
```

`/etc/custos/bootstrap.env` — temporary initialization only:

```ini
CUSTOS_DATABASE_URL='postgresql+psycopg://custos_inventory_bootstrap:URL_ENCODED_PASSWORD@db.example.com:5432/custos_inventory?sslmode=verify-full&sslrootcert=/etc/custos/ca/postgres-ca.pem'
CUSTOS_RBAC_ADMIN_DATABASE_URL='postgresql+psycopg://custos_rbac_bootstrap:URL_ENCODED_PASSWORD@db.example.com:5432/custos_rbac?sslmode=verify-full&sslrootcert=/etc/custos/ca/postgres-ca.pem'
```

The backend key protects hypervisor credentials/archives. The different RBAC key protects role mappings. The session key signs browser sessions. An environment variable named “reader” is not a security boundary: the PostgreSQL grants in the next step enforce it.

## 6. Initialize tables and bootstrap an administrator

Load only your own root-controlled environment files. The following initialization shell uses the bootstrap database identities temporarily:

```bash
sudo bash
set -a
. /etc/custos/keys.env
. /etc/custos/runtime.env
. /etc/custos/admin.env
. /etc/custos/bootstrap.env
set +a
cd /opt/custos
.venv/bin/custos-directory init-db
.venv/bin/python -m custos.rbac_cli init
exit
```

Now grant runtime table access as DBA:

```bash
sudo -u postgres psql
```

```sql
\connect custos_inventory
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO custos_inventory;
REVOKE UPDATE, DELETE ON audit_events FROM custos_inventory;
\connect custos_rbac
GRANT SELECT ON role_bindings TO custos_rbac_reader;
GRANT SELECT, INSERT, DELETE ON role_bindings TO custos_rbac_writer;
\quit
```

Create the first administrator using the **runtime** connections, not the bootstrap file:

```bash
sudo bash
set -a
. /etc/custos/keys.env
. /etc/custos/runtime.env
. /etc/custos/admin.env
set +a
cd /opt/custos
.venv/bin/custos-directory local-user-create custos-admin --display-name 'Custos Administrator' --admin
exit
```

The CLI prompts for a password. Ordinary local users use the same command without `--admin`. Existing users/groups can be bootstrapped deliberately with `python -m custos.rbac_cli grant-admin PRINCIPAL_ID`. Normal administration thereafter happens through the portal.

Remove bootstrap credentials from service hosts after provisioning, or retain them only in an approved restricted deployment secret store. Never include `bootstrap.env` in systemd services. Current initialization creates missing tables; it does not migrate changed columns. For upgrades, review schema changes and back up first. Reapply runtime grants when new tables are introduced; do not grant schema-owner rights to runtime accounts.

## 7. Run the app and worker as Linux services

Create `/etc/systemd/system/custos-web.service`:

```ini
[Unit]
Description=Custos web and console gateway
After=network-online.target
Wants=network-online.target

[Service]
User=custos
Group=custos
WorkingDirectory=/opt/custos
EnvironmentFile=/etc/custos/keys.env
EnvironmentFile=/etc/custos/runtime.env
EnvironmentFile=/etc/custos/admin.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/custos/.venv/bin/python -m uvicorn custos.console_gateway:create_gateway --factory --host 127.0.0.1 --port 8080 --proxy-headers --forwarded-allow-ips=127.0.0.1 --no-access-log
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/custos-worker.service`:

```ini
[Unit]
Description=Custos inventory and operation worker
After=network-online.target
Wants=network-online.target

[Service]
User=custos
Group=custos
WorkingDirectory=/opt/custos
EnvironmentFile=/etc/custos/keys.env
EnvironmentFile=/etc/custos/runtime.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/custos/.venv/bin/python -m custos.worker
Restart=on-failure
RestartSec=5
TimeoutStopSec=180
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

Systemd reads the root-owned environment files before dropping privileges. Public CA files must be readable by the `custos` user. Optional client private keys need narrowly scoped service read access; do not make them world-readable. The worker intentionally does not receive `admin.env`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now custos-web custos-worker
sudo systemctl status custos-web custos-worker
sudo journalctl -u custos-web -u custos-worker --since '10 minutes ago'
```

Do not use Flask's development server for deployment. Start the ASGI gateway to support HTTP and WebSockets together. Do not expose loopback port 8080 directly to users.

## 8. Configure HTTPS: choose nginx or Apache

Use **one**, not both on the same listening ports. Obtain a certificate for `custos.example.com` and put its chain/private key in the paths below. The configured public origin must match the browser URL exactly. Secure cookies require HTTPS.

### Option A — nginx

```bash
sudo apt install -y nginx
```

Create `/etc/nginx/sites-available/custos`. This file is loaded inside nginx's HTTP context on Ubuntu:

```nginx
map $http_upgrade $custos_connection {
    default upgrade;
    '' close;
}
map $uri $custos_login_key {
    default '';
    ~^/login $binary_remote_addr;
}
limit_req_zone $custos_login_key zone=custos_login:10m rate=10r/m;

server {
    listen 80;
    server_name custos.example.com;
    return 301 https://custos.example.com$request_uri;
}
server {
    listen 443 ssl;
    server_name custos.example.com;
    ssl_certificate /etc/ssl/custos/fullchain.pem;
    ssl_certificate_key /etc/ssl/custos/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 32k;
    limit_req zone=custos_login burst=10 nodelay;
    limit_req_status 429;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $custos_connection;
        proxy_read_timeout 660s;
        proxy_send_timeout 660s;
        proxy_buffering off;
    }
}
```

The login limit is a starting policy; tune it for PSM/shared egress without removing protection. An empty limit key exempts non-login paths. Enable the site after replacing certificate paths:

```bash
sudo ln -s /etc/nginx/sites-available/custos /etc/nginx/sites-enabled/custos
sudo nginx -t
sudo systemctl reload nginx
```

See [nginx WebSocket proxying](https://nginx.org/en/docs/http/websocket.html).

### Option B — Apache HTTP Server

Use Apache 2.4.47 or later. Add equivalent login rate limiting through your approved WAF/proxy policy; the example below does not itself implement a login limiter.

```bash
sudo apt install -y apache2
sudo a2enmod ssl proxy proxy_http proxy_wstunnel headers
```

Create `/etc/apache2/sites-available/custos.conf`:

```apache
<VirtualHost *:80>
    ServerName custos.example.com
    Redirect permanent / https://custos.example.com/
</VirtualHost>
<VirtualHost *:443>
    ServerName custos.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/custos/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/custos/privkey.pem
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    ProxyRequests Off
    ProxyPreserveHost On
    ProxyTimeout 660
    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass /console/ws/ ws://127.0.0.1:8080/console/ws/ timeout=660
    ProxyPassReverse /console/ws/ ws://127.0.0.1:8080/console/ws/
    ProxyPass / http://127.0.0.1:8080/ timeout=660
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

```bash
sudo a2ensite custos
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Keep the WebSocket rule before the general HTTP rule. See [Apache reverse proxy guidance](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html) and [WebSocket proxy support](https://httpd.apache.org/docs/2.4/mod/mod_proxy_wstunnel.html).

## 9. Connect the backend and assign resources

1. Open `https://custos.example.com/login` and sign in as the bootstrapped administrator. With no backend, Custos opens onboarding.
2. Select VMware vCenter 8.0 U3/9.x or Nutanix Prism Central AHV v4.0. Enter a name and HTTPS origin; Prism normally uses `:9440`.
3. Test the connection. For an untrusted certificate, independently verify its SHA-256 fingerprint, then accept backend-specific trust. Hostname/expiry checks still apply.
4. Enter the scoped service account and test API access. VMware reports effective VM privileges. Nutanix reports read access and unverified action privileges; verify the role/scope in Prism and acknowledge it explicitly.
5. Create/select a tenant, select VM UUID scope, choose a sync schedule, accept encrypted credential storage, and sync. Initial limits: 4,000 visible VMs, 200 selected VMs and 1,000 distinct IPs.
6. Create static or dynamic resource groups. Dynamic filters support VM-name regex, IP range/subnet, backend and tags. Preview membership. Multiple fields use AND.
7. Open User/group role mappings and map Read-only or Operator to a user/group and resource group. Custos admin is global. Creating a group alone grants no access.
8. Sign in as a normal user. Only mapped VMs should appear. Login refreshes their status: green powered-on, red powered-off/suspended, gray unavailable.

Each VM allows one console or mutation at a time across all users. Reboot requesters confirm guest completion and release their own lock in Activity. Green power does not prove a reboot finished. Admin release is exceptional recovery, not the routine workflow.

Admins can use Integrations to update API credentials, inspect/approve certificates, archive or restore a backend. A failed/unavailable backend shows a workspace banner and disables actions. Archiving removes active VM records and preserves encrypted recovery data/audit history; restore validates provider identity and UUID scope first.

## 10. Enable VM consoles

The ASGI broker is installed by the console extra and is the service started in step 7. No provider ticket is sent to the browser. Configure approved console destination hostnames and trusted issuing CAs in `runtime.env`.

**VMware:** obtain the licensed HTML Console SDK through your approved entitlement/download process. Set `CUSTOS_WEBMKS_ASSET_DIR` to an absolute directory containing `wmks.min.js`, `wmks-all.css`, compatible `jquery.min.js`, `jquery-ui.min.js` and accompanying SDK assets. These licensed files are not bundled. ESXi console certificates need trust independently of vCenter trust.

**Nutanix:** noVNC is bundled. The public token API is documented under v4.2+, despite a v4.0 example URL. The adapter defaults to `CUSTOS_NUTANIX_CONSOLE_API_VERSION=v4.2`; use v4.0 only where the actual endpoint is supported. Prism must supply the supported session cookie for the WebSocket handshake. Version, completion schema and authentication require live acceptance; unsupported flows fail closed.

A console authorization is single-use and expires after 30 seconds unused. Connected consoles last at most ten minutes, recheck access every five seconds, and close on logout/revocation. Console session auditing is included; keystroke/video recording is not. See [VMware SDK requirements](https://developer.broadcom.com/sdks/vmware-html-console-sdk/latest/) and [Nutanix console API guidance](https://www.nutanix.dev/2026/05/01/vm-console-external-access/).

## 11. Add AD/LDAP, PSM and external logging

**Directory import:** edit an example configuration under `/opt/custos/examples` (copy it to `/etc/custos` first if managing deployed configuration). Use an `env:VARIABLE_NAME` credential reference and supply the read-only bind secret through the sync process's protected environment. Configure both user and group filters; a group filter alone does not import its members. Run `custos-directory configure CONFIG.json`, then `preview DIRECTORY_ID`, then `sync DIRECTORY_ID`, with the same inventory URL as the services. Never import user passwords.

Directory imports currently run through the CLI; they are **not** scheduled by the backend inventory scheduler. Directory freshness defaults to 15 minutes, so arrange a supervised recurring sync comfortably within that interval, such as every five minutes, and monitor failures. A complete successful sync replaces effective membership atomically. Inspect `docs/identity-setup.md` for AD nested-group filters and generic LDAP schema limitations.

**PSM:** configure the web connection component to open `/login` for local accounts or `/login/directory/DIRECTORY_ID` for AD/LDAP. Inject credentials into `#username`/`#password`, click `#login-submit`, and preserve normal form/CSRF handling. Successful authentication opens the authorized workspace. Individual injected identities give individual audit attribution; a shared target account remains a shared identity.

**Syslog:** the worker reads `CUSTOS_SYSLOG_HOST`, transport and port from the runtime environment. TLS on 6514 is recommended; set its CA and optional client certificate/private key for mutual TLS. Events use RFC 5424 with UTC timestamps, UTF-8 JSON and correlation IDs. Admin Activity shows all users' events and pending transmissions. Outages retain records in a durable retry outbox; use `event_id` to deduplicate at the receiver. Socket transmission is not confirmation that a receiver stored the event. See [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) and [TLS transport](https://www.rfc-editor.org/rfc/rfc5425).

## 12. Expand to a cluster

1. Provision HA PostgreSQL endpoints for inventory and RBAC, with database TLS and the separate roles above.
2. Initialize schema once. Do not run unreviewed schema changes concurrently from every replica.
3. Deploy two or more identical app/gateway instances behind a TLS load balancer supporting WebSockets.
4. Share the corresponding signing/backend/RBAC keys and read-only vendor/CA assets across replicas. Never share a SQLite file.
5. Run at least two worker replicas with `CUSTOS_CLUSTER_MODE=true`. PostgreSQL advisory locking elects one cycle leader; followers can take over. This is active/passive job processing, not parallel mutation workers.
6. Give workers only RBAC reader access. Admin-capable web instances additionally receive the distinct RBAC writer credential.
7. Configure proxy-source trust explicitly for your load balancer addresses; the loopback-only Uvicorn command above is for the single-host proxy example.
8. Exercise app/worker/database failover before enabling production users. Interrupted mutations become unknown and are not replayed; per-VM locks remain until verified or requester-confirmed as applicable.

`Dockerfile` and `deployments/kubernetes/custos.yaml` provide build/deployment starting points. Replace the image placeholder, supply secrets, ingress, certificate mounts, health checks, disruption policy and network rules for your environment. Existing WebSockets do not migrate between app replicas; users open a fresh console after a disconnect. PostgreSQL HA itself must be supplied and validated by your infrastructure platform.

## 13. Acceptance and operational recommendations

Before onboarding production users, verify at least:

- Local/directory login and PSM injection; disabled-user and group-removal behavior.
- Read-only/operator/admin mappings, cross-tenant denial and dynamic-group previews.
- Current status, every enabled action on disposable VMs, two-user lock contention and requester reboot confirmation.
- Console launch, logout/revocation, unsupported-version handling and WebSocket proxy timeout behavior.
- Backend outages, failed credential updates, archive/restore and preserved audit history.
- All-user admin audit visibility, syslog outage/retry and collector parsing/deduplication.
- App/worker/database failover and recovery without duplicate VM commands.

Back up both databases and their encryption keys separately, and rehearse restore. Set an audit retention/export policy and monitor outbox growth, failed syncs, unavailable backends and long-held VM locks. Keep application releases, dependencies and provider versions under change control. Retain a separate infrastructure-admin break-glass path.

Current limitations to plan around: no automatic schema-migration framework, no implemented encryption-key rotation, no general snapshot cleanup/capacity policy, no console recording, no automatic proof of guest reboot completion, and limited provider/version acceptance so far. Local automated checks do not replace live backend, reverse-proxy or HA acceptance.

## 14. Quick troubleshooting

| Symptom | Check |
|---|---|
| Startup reports missing RBAC key/store | Separate RBAC database initialized; correct key; reader/writer URLs and grants; no silent fallback to legacy grants |
| Database certificate error | CA file readability, hostname/SAN, issuing chain and `sslmode=verify-full` |
| Login loops or session missing | Browser uses HTTPS; correct public origin; replicas share session key; clocks synchronized |
| Directory login stops working later | Last successful directory import is within the freshness window; recurring directory sync is actually running |
| No resources assigned | Resource group membership plus a user/group role binding; enabled VM/backend; correct tenant scope |
| All actions gray | Worker service, backend health freshness, API connectivity, certificates and account access |
| Console unavailable | ASGI service, vendor assets, allowed hosts/CA, WebSocket proxy and supported provider console API/authentication |
| VM stays locked | Pending task/console, unknown outcome or requester reboot confirmation; inspect Activity before recovery |
| Syslog queue grows | Worker, logger host/port, TLS trust/client certificate and receiver framing settings |

Use portal Activity and `journalctl` for diagnosis without dumping environment variables, credentials, provider ticket URLs or console frames into logs.
