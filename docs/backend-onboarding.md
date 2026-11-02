# Admin backend onboarding

The admin wizard currently supports VMware vCenter 8.0 U3 and 9.x. Nutanix is not
enabled yet. Effective privileges are checked through the vSphere Web Services API
so both target versions share an adapter; the detected version must match the
selected family. Live compatibility validation on both versions is still required.

## Server setup

Install the updated package and create the additional tables using
`custos-directory init-db`. The additions use separate tables and do not require
altering the previous schema. Earlier prototype schema changes still require a
migration if your database predates the nullable principal directory field.

Create a new trusted Custos administrator:

```powershell
.\.venv\Scripts\custos-directory local-user-create custos-admin --display-name 'Custos Administrator' --admin
```

Custos administration is an explicit database role, independent of AD group names,
the username "admin", provider privileges and tenant resource grants. Never infer
it from an injected PSM username or a browser parameter. The CLI flag creates a new
local administrator; existing/external role provisioning needs administrative tooling.

Supply `CUSTOS_ENCRYPTION_KEY` through your server secret store, separately from the
database and `CUSTOS_SESSION_SECRET`. A key can be generated with:

```powershell
.\.venv\Scripts\python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Transfer that output to your server secret store and protect/back it up separately.
Do not put it in source control, database backups or client-side configuration.
Fernet uses authenticated symmetric encryption. Both pending and saved backend
passwords are ciphertext; only server processes holding the key can decrypt them.
There is no reveal-password endpoint. Losing the key prevents recovery; someone
with access to the running process/key can decrypt secrets. Managed KMS/HSM and key
rotation are not implemented yet. Encryption keys are never generated silently.

## Wizard flow

1. An authenticated Custos administrator with no enabled backend is redirected to
   `/admin/backends/setup`. Existing deployments show an Add hypervisor backend link.
2. Select vCenter version, backend name and HTTPS origin; Test connection performs
   a TLS handshake without credentials. Internal management networks are supported;
   loopback, link-local/metadata, unspecified and multicast destinations are rejected.
   Enforce the approved management endpoints in deployment egress rules as well.
3. If normal server trust fails, inspect subject, issuer, SHA-256 fingerprint and
   expiry. Explicit acceptance imports the presented certificate into the backend's
   **Custos trust store**, not the host-wide OS store. The next handshake still checks
   hostname and validity; expired or mismatched certificates are not bypassed.
   Trust is pending in the admin-owned draft until setup is completed. Restart
   discards pending trust. Changed certificates need a new approval workflow.
4. Enter the dedicated service identity/password and Test API. Custos authenticates,
   retrieves version, vCenter UUID and visible VMs, then queries effective privileges
   for the current provider session on each VM. The report shows available and missing
   actions. No power, snapshot or console operation is executed during this check.
5. Select static VM scope and an existing/new tenant. The initial onboarding limit is
   4,000 visible VMs, 200 selected VMs and 1,000 distinct IPs. Every selected VM must
   have all required privileges. A lower-privilege account is rejected before import;
   use Change credentials or repeat API test after fixing the provider role.
6. Accept the report and encrypted storage, then sync. Custos rechecks vCenter identity,
   selected UUIDs and privileges, resolves every usable guest IPv4/IPv6 address, and
   confirms PTR names against A/AAAA responses. Failed DNS lookups preserve the IP
   with no DNS name. Up to eight DNS lookups run concurrently with bounded DNS calls.
   Loopback/link-local/unspecified/multicast guest addresses are excluded.
7. Save backend configuration, encrypted credential, selected UUID scope and VM/IP
   mappings in one database transaction. The completion page closes the wizard flow
   with a return-to-workspace link. Importing creates no tenant resource grants.

Wizard drafts are owned by the initiating administrator, expire after 30 minutes,
and are checked on each request. Draft expiry prevents use but unused expired rows
need later maintenance cleanup. Browser sessions contain only the draft ID, not the
backend password or report. CSRF tokens protect every change.

## Provider role and status

Required privileges are `System.View`, `System.Read`,
`VirtualMachine.Interact.ConsoleInteract`, `VirtualMachine.Interact.PowerOn`,
`VirtualMachine.Interact.PowerOff`, `VirtualMachine.Interact.Reset`, and
`VirtualMachine.State.CreateSnapshot`, on each selected VM. Reboot/reset and graceful
shutdown/hard power-off share provider privileges, so later execution methods must
still enforce the narrower Custos permissions. Effective permissions are checked;
the wizard does not depend on a role being named "VM Operator".

Inventory stores Custos ID, provider instance UUID, managed-object reference, VM
name, power/Tools status, all discovered usable IPs, confirmed DNS names and refresh
times. vCenter instance UUID uniqueness prevents duplicate backend registration.
The worker queries only inventory visible to the service identity; it cannot report
on invisible VMs. Templates may be visible but runtime operations can still be
unsupported; privileges alone do not prove runtime action readiness.

The initial onboarding sync remains synchronous. Recurring schedules and a VM action
worker are now implemented; see [operations and audit](operations-and-audit.md).
Long-running production sync needs durable jobs and progress polling. Inventory view
view now displays the last refresh timestamp for scheduled records, and every action
checks current provider state. Backend configuration editing/key rotation, dynamic provider
scope, automated certificate renewal and deployment hardening remain future work.

Reference: [vSphere AuthorizationManager privilege checks](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.AuthorizationManager.html).
