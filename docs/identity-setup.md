# Local and directory identities

Custos stores local users and scoped external identities in its own database. This
is the identity portion of the Custos CMDB; no separate external CMDB connector is
implemented. Creating or importing an account grants no tenant or VM permissions.

## Initialize a new development database

From the repository root, install with `.venv\Scripts\python -m pip install -e .`.
Then run `.venv\Scripts\custos-directory init-db`. The default database is
`sqlite:///custos.db`, relative to the working directory. All commands accept
`--database URL` before the subcommand. Production PostgreSQL driver/configuration
and schema migrations remain pending. `init-db` creates missing tables; it does not
alter existing tables. Use a fresh development database for the new nullable
principal directory field; do not run against an older schema without a migration.

## Local accounts

```powershell
.\.venv\Scripts\custos-directory local-user-create psm-custos --display-name 'Custos PSM account'
```

The CLI prompts for and confirms a password (12–1024 characters). It stores a unique
salt and scrypt hash, never a plaintext password. Local usernames are case insensitive
and occupy their own namespace; directory sync cannot overwrite local accounts.
Disabled local accounts cannot log in. The initial CLI creates users only; local
group administration and password rotation/reset tools remain to be added.

## Scoped AD/LDAP sync

Create a read-only service identity in AD/LDAP with access only to the required
search bases/attributes. Custos configures the connection; it does not provision AD
accounts. Copy and edit `examples/ad-directory.json` or `examples/ldap-directory.json`.
The JSON stores the bind username and a secret reference, not the password.

```powershell
.\.venv\Scripts\custos-directory configure examples/ad-directory.json
$bindSecret = Read-Host 'Directory sync password' -AsSecureString
$env:CUSTOS_AD_BIND_PASSWORD = [System.Net.NetworkCredential]::new('', $bindSecret).Password
.\.venv\Scripts\custos-directory preview corporate-ad
.\.venv\Scripts\custos-directory sync corporate-ad
Remove-Item Env:CUSTOS_AD_BIND_PASSWORD
```

Only `env:VARIABLE_NAME` secret references are implemented currently; inject secrets
from your deployment's secret store for unattended execution. LDAPS validates the
certificate and hostname; `ldap://` requires StartTLS before binding. Set `ca_bundle`
to your CA PEM path when using a private CA. Referrals are not followed.

Both filters are explicit, trusted administrator configuration:

- One AD user: `(sAMAccountName=alice)`.
- Several AD users: `(|(sAMAccountName=alice)(sAMAccountName=bob))`.
- Users under an AD group, including nested membership:
  `(memberOf:1.2.840.113556.1.4.1941:=CN=Custos-Users,OU=Groups,DC=example,DC=com)`.
- Imported group: `(cn=Custos-Users)`; a DN-based filter can distinguish duplicate CNs.
- Import users only: set group filter to `(!(objectClass=*))`.

User and group filters are independent scopes. A group filter alone does not import
all its users: set the user filter to the corresponding memberOf expression. Final
group membership includes only users inside the user scope. AD primary-group
membership is not expanded by memberOf; use an explicit access group. Disabled AD
users are excluded. Expiry/lockout are not a complete AD authentication decision.

AD uses immutable objectGUIDs and transitive group membership queries. Generic LDAP
currently supports inetOrgPerson users with entryUUID and groupOfNames groups with
DN-valued member attributes, direct membership only. Generic account-disabled flags
must be excluded in your user filter. Other schemas and nested generic LDAP groups
need adapters. Group lookup and user lookup share the configured base DN.

Searches are paged and bounded. Failed, truncated, referred or unsupported paging
results abort the import. AD ranged member attributes currently require a narrower
scope. Success upserts stable IDs, updates display names, replaces effective
memberships and disables previously imported identities no longer in scope, all in
one DB transaction. No grant rows are created or deleted. Empty imports require
`--allow-empty`; use this explicitly after preview to disable the whole scope.
Reconfiguring a directory invalidates its freshness until the next successful sync.

Run one sync process per SQLite DB; PostgreSQL imports lock the directory row.
Scheduling, durable sync history and change reporting remain future work. LDAP is
not a transactional snapshot: directory changes during a search can require reruns.

## Login and CyberArk PSM → Custos

The Flask login supports local accounts at `/login` and synced AD/LDAP accounts at
`/login/directory/<directory-id>`, e.g. `/login/directory/corporate-ad`. Configure the
appropriate URL in PSM. AD accepts UPN or sAMAccountName; generic LDAP accepts uid.
There is no automatic fallback between local and directory credentials.

Directory authentication uses the configured read-only sync identity to locate a
unique enabled user within the configured filter, then binds over verified TLS as
that user's resolved DN using the injected password. Its immutable objectGUID or
entryUUID must match an enabled, previously synced Custos identity. Empty passwords,
ambiguous results, missing identities, stale sync and LDAP failures deny login.
User passwords are neither imported nor retained in the session/database. This is
credential-injection login; federated OIDC/SAML and Kerberos are not implemented.

Set `CUSTOS_SESSION_SECRET` to a persistent random secret and `CUSTOS_DATABASE_URL`
to the same database URL as the CLI. Run from the repository root:

```powershell
.\.venv\Scripts\python -m flask --app web.app:create_app run --host 127.0.0.1 --port 8080
```

Secure cookies require HTTPS. Use a trusted TLS reverse proxy in front of Custos
before testing a real PSM connection; apply login rate limits there. The development
server is not a production deployment. Login uses CSRF tokens, HttpOnly/SameSite
cookies and a 15-minute signed session; logout is a CSRF-protected POST to `/logout`.
Successful login redirects to `/`, which reads VM records from the Custos DB and
shows only enabled VMs with a current `view` grant and tenant membership.
DNS name (or inventory-name fallback), IP, tenant, provider, power status and refresh
time are displayed. Start, Stop, Reboot, Reset and snapshot requests use the persistent
worker queue; see [operations and audit](operations-and-audit.md). Console is pending.
An account without visible VMs sees "No resources assigned".
Every page load rechecks the account, directory state and database permissions;
revoked view grants remove resources without requiring the user to sign in again.

Configure a CyberArk PSM Web Connection Component targeting `https://custos-host/login`:

- Vault the intended **Custos local or individual AD account**, not the vCenter service account.
- Fill username using `#username`, password using `#password`, click `#login-submit`.
- Let the browser load and submit the normal form, including its CSRF token.
- On success, expect the workspace at `/`; no second manual login is required.
- Configure the permitted URL and certificate trust on the PSM host.
- Assign explicit tenant/resource grants to that Custos account when admin tooling
  is available. Do not grant global administrator access just because PSM launched it.

This supplies a connector-compatible login surface, not an installed or certified
CyberArk connector. Connector packaging and live validation depend on your CyberArk
version. Custos sees the dedicated account; a shared account does not identify the
human operator. Per-person attribution requires individual accounts or a validated
SSO/session-correlation integration with CyberArk audit records. Caller-supplied
identity headers or URL parameters are not trusted.

References: [ldap3 connection/paging](https://ldap3.readthedocs.io/en/latest/connection.html),
[TLS](https://ldap3.readthedocs.io/en/latest/ssltls.html),
[AD filter syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax),
[CyberArk Web Connection Component checklist](https://github.com/cyberark/Idira-Partner-Integration-Docs/blob/main/docs/psm-connectors/web-connection-component/certification-checklist.md).
