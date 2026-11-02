# Resource groups

Custos admins can create groups at `/admin/resource-groups` using the workspace link.
Groups always belong to one tenant. Preview matches before creating a group.
Creation is audited; it does not automatically grant access.

**Static:** select individual VMs. Only VMs in the selected tenant can be added;
membership stays fixed until explicitly changed.

**Dynamic:** fill one or more rule fields. All fields in a group must match (AND).
The rule is evaluated against the current stored inventory whenever access is checked;
new/updated synced inventory automatically changes membership. Multiple grants/groups
combine additively. Rules never bring resources across tenant boundaries.

Supported rules:

| Field | Example | Behavior |
|---|---|---|
| VM-name regex | `^APP-(WEB\|DB)-[0-9]+$` | Searches provider inventory name, not DNS display name; case sensitive unless `(?i)` is included |
| Subnet | `10.20.30.0/24` or `2001:db8::/64` | Any discovered IP inside CIDR; CIDR must use the network address |
| IP range | `10.20.30.10` through `10.20.30.100` | Inclusive endpoints; both must be IPv4 or both IPv6 |
| Backend ID (JSON) | `{"remote_system_id":"vc-id"}` | Exact backend match |
| Tags (JSON) | `{"tags":{"environment":"dev"}}` | All tag pairs match |

Advanced JSON overrides individual rule fields. Example:

```json
{
  "name_regex": "^APP-",
  "subnet": "10.20.30.0/24",
  "ip_range": {"start": "10.20.30.10", "end": "10.20.30.100"}
}
```

When both subnet and range are given, the same IP must satisfy both. All IPs in
`vm_addresses` plus the primary IP are considered; malformed/missing addresses do not
match. Regex patterns are limited to 256 characters, matched names to 1024 characters,
and each match to 20 ms. Invalid/unknown rules and timeouts deny membership.

User/group assignments still use `grants` with a resource group, principal and action,
plus `tenant_members`. The new admin page creates/previews groups; grant editing and
editing existing group membership need a separate management UI. The existing
database supports both user and synced directory-group grants.
