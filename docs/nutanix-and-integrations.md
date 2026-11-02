# Nutanix and integration lifecycle

## Nutanix scope

The provider adapter targets **Prism Central managing AHV with stable v4.0 APIs**,
as confirmed for the intended environment. Select Nutanix Prism Central (AHV) and
Nutanix AHV v4.0 during onboarding; the usual HTTPS endpoint is port 9440. Prism
Element, v3 APIs and Nutanix-managed ESXi are not supported by this adapter.

The adapter uses documented v4.0 REST paths for AHV VM inventory, power-on, NGT guest
shutdown/reboot, hard reset, recovery-point creation and Prism tasks. The same
encrypted credential store, static UUID sync scope, DNS enrichment, schedules,
isolated RBAC, login status, operation queue, cross-user locks and audit view apply
to both providers. Nutanix extId is used as stable VM identity and API reference.
The Prism Central identity is verified using the read-only domain-manager API;
the service account must be allowed to read that identity. The existing
`backend_configs.vcenter_uid` field stores a provider-qualified `nutanix:<extId>`
value for backward schema compatibility.

The adapter verifies inventory-read access during setup. It does **not** infer
effective VM action privileges from inventory access or an operator role name.
Action permissions are shown as unverified and the admin must explicitly attest
that the account's VM operator scope was checked in Prism Central. That acceptance
is audited. Actual actions enforce Nutanix permissions; 401/403 responses are recorded
as failures. Automated Nutanix effective-permission preflight remains a limitation.

NGT must be reachable for guest shutdown/reboot; no hard-action fallback is used.
Mutations include `Ntnx-Request-Id`, and VM power actions require the current ETag
through If-Match. Requests never follow redirects or retry mutations automatically.
Returned task references are captured server-side and persisted with the requesting
Custos operation. Terminal provider task state controls locks. Shutdown additionally
requires reported power-off. NGT reboot remains accepted until explicit outcome
reconciliation; task acceptance alone does not prove guest reboot completed.

Snapshot maps to a **crash-consistent recovery point**, with an initial seven-day
expiration request and a limit of three visible recovery points for the VM. This is
not identical to a VMware snapshot. Recovery-point read/create permission and the
appropriate Nutanix data-protection capability/license must be validated on the
deployed system. Console still requires the separate broker and is not enabled.

v4.0 AHV NIC fields inspected for this implementation expose configured/learned IPv4
addresses. These feed the shared DNS and dynamic-group pipeline. IPv6 inventory
needs a separately documented compatible schema/version; it is not invented from
an unsupported response shape.

## Admin integration maintenance

Use `/admin/integrations` to view configured backends and health, test access, or
update HTTPS endpoint, service username and encrypted password. Blank passwords
retain the current secret. Proposed changes are saved only after validating provider
identity and the complete mapped UUID scope. VMware also checks required VM operator
privileges; Nutanix requires explicit role/scope attestation.

Inspect untrusted certificate obtains a credential-free certificate preview. Explicit
acceptance verifies hostname/expiry and stores backend-specific trust. Trust changes
mark the integration unavailable until a successful API test/update. Certificate
approval drafts are owned by the current admin and expire after 30 minutes. No
password-reveal endpoint exists. Admin actions and failures are audited.

## Health and action blocking

Onboarding, login checks and scheduled sync update backend health. The running worker
checks a mapped VM on each backend at most once per minute, separately from the
inventory schedule. Missing or older-than-two-minute health is unavailable. An
unavailable backend displays a banner at the top of the workspace and disables all
affected VM controls. Lock polling updates this state every five seconds, and both
the POST handler and worker reject dispatch while unavailable. Current provider
checks still run at action execution.

This detects failures on checks, not at the instant a network cable is disconnected.
Keep the worker running; stopping it eventually disables actions when health expires.
An API-test failure marks the tested integration unavailable until revalidated.

## Archive and restore

Archiving requires confirmation and is blocked during queued/executing/unresolved
operations or active inventory sync. The operation copies backend configuration,
encrypted credentials, schedules, VM identities, all IP records, static VM links and
terminal operation history into an **encrypted archive payload**, then removes those
rows from active inventory in the same transaction. Audit records remain active
and retain the original IDs; they are never deleted with an integration.

Shared resource-group definitions and encrypted RBAC policies remain, but with no
active backend/VM rows they confer no access to the archived resources, including
for Custos admins. Shared groups may still legitimately match other active backends.
Archiving does not delete unrelated resources or another tenant's group definitions.

Restore decrypts the archive, reconnects with the saved credential, verifies the same
provider identity and requires the full archived VM UUID scope to be visible. It
restores original IDs/static links/history, updates current power status, and requests
an immediate inventory refresh. Existing role mappings apply again; mappings revoked
while archived stay revoked. Restoring into conflicting active IDs fails atomically.
If archived credentials or certificates no longer work, restore fails without granting
access; archive-secret editing/recovery needs later admin tooling.

Run `custos-directory init-db` for the new health/archive tables. Restore/archive were
tested locally with mocks; external provider/version acceptance is still pending.

Official references: [VM API](https://developers.nutanix.com/api/v1/sdk/namespaces/main/vmm/versions/v4.0/languages/python/ntnx_vmm_py_client.api.vm_api.html),
[recovery points](https://developers.nutanix.com/api/v1/sdk/namespaces/main/dataprotection/versions/v4.0/languages/python/ntnx_dataprotection_py_client.api.recovery_points_api.html),
[Nutanix API usage and request IDs](https://www.nutanix.dev/nutanix-api-user-guide/).
