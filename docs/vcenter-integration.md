# vCenter integration

## Step 1: read-only adapter

Target environments: vCenter 8.0 U3 and 9.x. Compatibility is documentation-based;
neither version has been exercised against a live server yet.

The operator CLI creates an API session, lists the inventory visible to its service
account and deletes the session. It verifies HTTPS certificates, rejects redirects,
uses bounded timeouts and hides raw provider errors and session tokens. The existing
Flask page remains a mock until identity and VM entitlements are implemented.

### Install and run (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
$env:CUSTOS_VCENTER_URL = 'https://vcenter.example.com'
$env:CUSTOS_VCENTER_USERNAME = 'custos-reader@example.com'
# Optional: PEM file containing your private issuing CA chain.
$env:CUSTOS_VCENTER_CA_BUNDLE = 'C:\certificates\vcenter-ca.pem'
.\.venv\Scripts\custos vcenter-check
```

The password is prompted without echo. Automated operators may inject
`CUSTOS_VCENTER_PASSWORD` through a secret manager. No .env file is loaded
automatically. Use a dedicated account with read-only permission scoped to the test
VM folder. Results reflect provider permissions, not Custos project entitlements;
this CLI is for trusted operators only. No permission changes are made by Custos.

The VM list API returns at most 4,000 matching VMs and errors when that limit is
exceeded. This first adapter fails explicitly in that case; inventory partitioning
must be added before using larger inventories.

### Verification

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

Tests mock HTTP responses: session creation and cleanup, inventory mapping,
TLS and redirect settings, invalid origins, authentication failures and transport
error redaction. Live acceptance on **both** target versions remains required:
trusted/private CA connection; invalid CA rejection; scoped VM visibility; wrong
password and denied permission handling; session invalidation after completion.

## Next implementation steps

The expanded [database and access model](access-model.md) adds remote-system service
identities, VM UUID mappings, DNS/IP display, LDAP/AD principals, static/dynamic
resource groups and separate reboot/reset permissions. Initial relational models
and authorization evaluation are implemented; synchronization workers are pending.

1. Identity, project membership and VM-specific entitlements with negative access tests.
2. Database migrations, durable operations and audit records.
3. Authorized Start and graceful guest Shutdown, with per-VM concurrency,
   idempotency and provider outcome checks. Do not use hard power-off for Stop.
4. Snapshot creation with policy, task tracking, retention and cleanup ownership.
5. Separate console broker with short-lived authorization; validate VMware console
   protocol and endpoint requirements on each deployed version.
6. Live integration and security acceptance, then deployment hardening.

No live mutation or console endpoint is implemented in step 1.

## Official API references

- [Session create](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/cis/api/session/post/)
- [VM inventory](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/vm/get/)
- [vSphere Automation API](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/)
