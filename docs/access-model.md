# Inventory, identity and access design

This specification supersedes the original four-action scope. Supported permissions
are View status, Console, Start, Stop (graceful shutdown), Reboot (guest OS), Reset
(hard reset), and Create snapshot. Each permission is granted independently in Custos.

## Remote systems and service identities

Register each vCenter in `remote_systems`, including endpoint, service username,
enabled state and a secret-manager credential reference. Store no plaintext password
in the database. Provision a dedicated custom-role service account on the provider,
scoped to managed VM folders. Custos never grants provider permissions automatically.
One account per remote system is the initial deployment model.

The account can read inventory/status and execute only the approved operations.
Required vSphere privileges include ConsoleInteract, PowerOn, PowerOff, Reset and
CreateSnapshot under the respective VirtualMachine privilege categories. Validate
the final role on both 8.0 U3 and 9.x, including required read visibility.

Provider permissions are coarser than Custos permissions: guest reboot and hard reset
share `VirtualMachine.Interact.Reset`; graceful shutdown and hard power-off share
`VirtualMachine.Interact.PowerOff`. Custos must restrict callable methods as well as
authorize each request. There is no automatic escalation from guest shutdown to
power-off or from guest reboot to reset. Snapshot means create only; cleanup is a
separate maintenance identity/workflow. Console tickets remain in the isolated broker.

Reference: [official VM methods and required privileges](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.VirtualMachine.html).

## VM mapping and tenant display

`vms.id` is the Custos UUID. `(remote_system_id, provider_uid)` uniquely identifies a
VM using vCenter's instance UUID; `provider_ref` stores the current managed-object
reference used for API calls. Inventory sync must retrieve the UUID explicitly; the
existing summary-list adapter supplies only the managed-object reference. Never map
permissions by name, IP, DNS, or BIOS UUID alone. Recreated/cloned/moved VMs require
identity reconciliation; never silently transfer grants based on a reused reference.

Each VM belongs to one tenant initially. Unassigned discoveries are kept out of the
tenant inventory until assigned. Store power/Tools status, observation time, tags,
selected guest IP, DNS result and resolution time. Add a separate address table when
implementing multi-NIC IPv4/IPv6 discovery. IP may be missing or stale when Tools are
unavailable; it is not a reachability check.

Tenant display: validated reverse-DNS name, otherwise inventory name; show selected
IP, power status and last refresh. DNS enrichment runs in a bounded background worker
through approved resolvers, with caching and forward confirmation of PTR results.
Escape all names in the UI. DNS never determines identity or grants access. No DNS
worker or live status synchronization has been implemented yet.

## Directory synchronization

`directories` holds LDAP/AD source configuration and secret references. `principals`
stores users and groups by source plus immutable external identity (AD objectGUID or
LDAP entryUUID); names and DNs may change. `group_members` stores effective user
membership. The planned sync worker expands nested groups with cycle detection and
publishes membership atomically only after a complete successful sync. Disable removed
or disabled users/groups; revoked membership must stop granting access. Use LDAPS or
validated StartTLS and a read-only directory bind identity.

Scoped directory synchronization and local account login are now implemented; see
[identity setup](identity-setup.md). Directory sync is not login. Authentication must bind a validated session subject to
the synced principal ID; never accept a browser-supplied user ID. Cross-directory
group membership is not supported initially. Synced users can now authenticate using
the directory-specific login URL with AD/LDAP credential verification.

## Resource groups and grants

`tenant_members` admits a user or group to a tenant. `resource_groups` is tenant-scoped:

- Static groups explicitly list VMs in `resource_group_vms`.
- Dynamic groups use allowlisted equality rules, evaluated with AND semantics, e.g.
  `{"remote_system_id":"vc-id","tags":{"environment":"dev","application":"billing"}}`.

`grants` connects a user or directory group to a resource group and one action.
Direct-user and group grants combine additively. Unknown actions/rules are denied.
Tenant membership alone grants no resource visibility. Administering rules, tenant
assignments, tags and grants requires a separate trusted administrator role because
editing a matching tag may change access. Use provider-controlled tags initially.

`authorization.permitted` checks enabled identities and systems, fresh directory
and VM observations, tenant membership and matching grants. Defaults are 15 minutes
for directory freshness and 5 minutes for VM observations. These are initial policy
defaults, not a running sync schedule. Static membership has composite database
foreign keys to prevent crossing tenants. Production authorization must use fresh
database reads at execution, and revalidate capabilities and current provider state.

## Implementation status

Implemented: SQLAlchemy table foundation, deny-by-default policy evaluation, scoped
LDAP/AD imports, local and directory account login for PSM web connector configuration,
and a database-backed workspace filtered by current view and action grants.
SQLite is used for isolated tests; PostgreSQL remains the production target.
Schema migrations, provisioning/admin APIs, scheduled sync, inventory synchronization,
DNS enrichment, federated SSO, durable jobs/audit, live actions and console broker are next.
The workspace shows authorized database records; live vCenter inventory sync remains pending.
