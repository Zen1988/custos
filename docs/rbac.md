# Simple RBAC with isolated policy storage

This supersedes the original per-action grant model for configured web/worker
deployments. There are two resource roles and one global administrative role:

| Role | Scope | Permissions |
|---|---|---|
| Read-only | Mapped resource groups | View VM DNS names and status |
| Operator | Mapped resource groups | View plus console/start/stop/reboot/reset/snapshot permissions |
| Custos admin | All resources and tenants | Portal administration and all VM permissions |

The console permission is included in the operator role, but its broker is still
pending. Runtime provider capability checks, explicit confirmation and global VM
operation locks apply to operators and admins equally. Admins cannot bypass locks.

## Mapping

Open Resource groups → User/group role mappings (`/admin/role-mappings`). Select an
enabled user or synced directory group, resource group and Read-only/Operator role.
Select Custos admin for global access; no resource group is required. Multiple
bindings combine additively. Group membership revocation and disabled principals
are checked on every request and again before queued work executes.

Each row in the separate `role_bindings` table has an opaque binding ID and encrypted
authenticated policy containing subject ID/type, role, tenant/resource-group scope,
static VM IDs or dynamic rules. Mapping scope is an encrypted snapshot of the group
definition. Dynamic VM facts continue updating normally, but editing an inventory-side
group definition cannot broaden an existing mapping. Remove and recreate the mapping
to approve a changed definition. Removal takes effect on the next authorization check.
The binding itself conveys access to its group's tenant; a second legacy tenant
membership row is not required. Raw inventory `grants`/`admin_roles` rows are ignored
by isolated deployments. Legacy tables remain for old tests/data, not as a fallback
when the isolated store fails.

## Database and encryption separation

- `CUSTOS_DATABASE_URL`: inventory, identities, jobs and audits.
- `CUSTOS_RBAC_DATABASE_URL`: separate policy database, using a **read-only** DB identity.
- `CUSTOS_RBAC_ADMIN_DATABASE_URL`: same policy database with a distinct writer identity;
  provide only to the admin web process and bootstrap tooling.
- `CUSTOS_RBAC_KEY`: independent Fernet key for policy encryption; it must differ from
  `CUSTOS_ENCRYPTION_KEY`, which protects hypervisor passwords.

The worker opens only the RBAC reader connection. Normal authorization never writes
policies. The admin process can use the writer only after authenticating an authorized
Custos admin. SQL grants must enforce the connection privileges; variable names alone
do not make a database account read-only. The application rejects using the inventory
database for RBAC and, for PostgreSQL, rejects reusing inventory credentials or sharing
one identity between RBAC reader and writer.

Use a separate PostgreSQL database/server and restricted DB users for production.
Install `.venv\Scripts\python -m pip install -e '.[postgres]'` for the driver. As DBA,
provision a policy database owned by a non-login schema owner, migration access for
bootstrap, a SELECT-only reader, and a writer with SELECT/INSERT/DELETE on
`role_bindings` (no UPDATE/DDL). Revoke PUBLIC connection/schema access as appropriate;
do not grant the inventory identity access to the RBAC database. Apply network/TLS
restrictions too. Database provisioning is deployment work; no external PostgreSQL
instance has been provisioned or validated here.

SQLite can use `sqlite:///custos-rbac.db` as a separate development file, but SQLite
has no separate DB login roles. It does **not** provide production credential/instance
isolation. OS file permissions and separate service identities are required even for
local separation. Both files must be backed up independently; keep both encryption
keys outside their respective backups. Encryption protects policy contents/integrity,
not compromise of a running process that already holds the key.

Identity records and effective directory membership still live in the identity/
inventory database. Protect that authority too: this policy-store split does not
make a compromised identity database or full application process trustworthy.

## Initialize and bootstrap

Generate a new Fernet key, independently of the backend key, and install it as
`CUSTOS_RBAC_KEY` in your server secret store. Configure reader/writer URLs as above.
Production web startup requires the RBAC key; missing/wrong keys do not silently
fall back to old grants.

```powershell
# Inventory tables first.
.\.venv\Scripts\custos-directory init-db
# Use the RBAC schema-owner/migration identity as the admin URL for initialization.
.\.venv\Scripts\python -m custos.rbac_cli init
# Then switch the admin URL to the restricted RBAC writer identity.
.\.venv\Scripts\custos-directory local-user-create custos-admin --display-name 'Custos Admin' --admin
```

For an existing enabled user or directory group, bootstrap deliberately using its
principal ID: `python -m custos.rbac_cli grant-admin <principal-id>`. This is a trusted
deployment command, not a user-accessible API. Existing legacy grants/admins are not
silently migrated: bootstrap one administrator, then explicitly assign the new roles.

Policy writes and main audit writes are independent database transactions. A durable
audit intent precedes web role changes; a completion event follows. Inspect intents
without completion after an outage. Removing your final administrator mapping can
lock you out; recovery uses the trusted bootstrap CLI. Key rotation and automated
cross-database recovery remain pending.

Tests use separate temporary SQLite databases for isolation, encryption, role checks,
revocation and the mapping page. PostgreSQL privilege enforcement needs deployment
acceptance testing. Legacy unit fixtures bypass isolated storage only in explicit
Flask TESTING mode or unconfigured low-level test sessions; normal web startup and
the worker always attach the isolated store.

References: [PostgreSQL privileges](https://www.postgresql.org/docs/16/ddl-priv.html),
[Fernet authenticated encryption](https://cryptography.io/en/stable/fernet/).
