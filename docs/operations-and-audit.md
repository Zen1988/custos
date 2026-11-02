# Schedules, actions, VM locks and audit

## Run the worker

Run `custos-directory init-db` to create the new schedule, operation, lock and audit
tables. Existing records are preserved; these changes add tables only. Install the
updated package with `.venv\Scripts\python -m pip install -e .` to refresh CLI entry
points, then run exactly **one** worker process beside the web service:

```powershell
.\.venv\Scripts\python -m custos.worker
```

The worker needs the same `CUSTOS_DATABASE_URL` and `CUSTOS_ENCRYPTION_KEY` as the web
service. Run it as a supervised service for unattended operation. It is not started
by Flask and a saved schedule cannot run while the worker is stopped. `--once` runs
one cycle for verification. SQLite is for a single local deployment; deploy with
PostgreSQL for production. Multiple web requests share DB constraints, but running
multiple worker processes is not supported: worker startup reconciles interrupted
executing operations to unknown and must not overlap an already-running worker.

## Inventory schedules

The setup scope page now offers every 5 minutes, hourly, daily (24 hours), weekly,
or manual. Intervals run from setup/last scheduling in UTC, not a calendar timezone.
Admins can edit schedules and request Sync now from Activity. The worker claims due
schedule rows atomically and records start/success/failure. Sync updates only stored
VM UUID scope, reconciles provider references, refreshes status and all usable guest
IPs/DNS, and disables mapped VMs that are no longer visible. Failed provider syncs
preserve the previous inventory and create a failure event.

Successful local or directory login now performs a read-only live status check for
only the user's authorized VMs through the shared backend account. The compact
workspace shows DNS name (inventory-name fallback if unresolved), a green indicator
for powered-on, red for powered-off/suspended, and gray if the live check is unavailable.
IP, provider and timestamp columns are omitted. This is hypervisor power status,
not guest application/network health. Login checks are audited as `vm.login_status`.
The login refresh does not execute VM operations or alter their locks. Scheduled
inventory sync continues independently. Before every action, the provider is contacted again to verify VM identity,
current state, VMware Tools capability and effective action privilege. Directory
identity/membership freshness checks still apply independently.

## Shared backend account and durable operations

Start, graceful Stop, guest Reboot, hard Reset and Create snapshot now submit through
the registered vCenter service identity. The signed-in Custos principal is recorded
as requester; the operator account and provider task ID are recorded with the result.
Users cannot supply provider credentials, endpoint URLs or arbitrary SDK methods.
Console is still excluded until the isolated console broker is implemented.

Each request requires CSRF protection, confirmation, view permission, explicit action
permission and registered UUID scope. An idempotency key prevents a repeated form
submission from creating a second operation. The queue record, initial audit event
and VM lock are committed before the worker can contact vCenter. The worker checks
authorization again immediately before dispatch. A revoked grant blocks queued work.

The `vm_operation_locks` primary key is the VM ID. It prevents every other user and
browser session from queuing any action against the same VM. The workspace disables
all action controls and polls shared lock status every five seconds. Stale pages or
direct POSTs cannot bypass the database constraint; they receive HTTP 409.

Power-on, reset and snapshot wait for vCenter task success/error. Graceful shutdown
waits for vCenter to report powered-off. Terminal success/failure releases the lock.
Task polling is bounded to 120 seconds; timeout, transport ambiguity, worker crash
or missing outcome retains the lock and never automatically replays the mutation.
The worker later polls saved task references and shutdown state; provider-confirmed
completion releases the lock and adds a new audit event.

**Requester confirmation for reboot:** after submission, the initiating Custos user
sees "Your reboot confirmations" in Activity. That user checks the guest, confirms
completion and releases the VM lock; an admin is not needed for the normal flow.
Other users cannot confirm someone else's reboot. Queued/executing requests cannot
be released early, and green power/provider task status never releases a reboot lock.
The confirmation is audited as `vm.reboot.confirm` / `user_confirmed`, distinct from
provider-proven success. Optional notes are recorded. Administrative reconciliation
remains an exceptional recovery route if the requester cannot finish the workflow.

**Guest reboot is special:** VMware RebootGuest returns without a task or guest-OS
completion report. Custos records `accepted` and retains the lock. It does not treat
VMware Tools restarting as proof of reboot completion. The requester verifies the
outcome and releases the lock from Activity; automatic guest completion needs an
additional trusted guest-health integration. Emergency admin reconciliation requires explicit
confirmation and notes, records who performed it, and releases the lock without
retrying. The audit preserves the original accepted/unknown outcome.

The locks coordinate Custos operations, not commands run independently in vCenter.
The initial worker processes operations sequentially. Snapshot creation uses a fixed
`custos-<operation-id>` name, disk-only/non-quiesced snapshots, and a limit of three
existing snapshots. Retention, capacity policy and snapshot cleanup remain pending.
No hard power-off fallback is used for Stop; Reboot never becomes a hard Reset.

## Web audit

Open `/activity` or the workspace Activity link. Administrators see all users and
system events; other users see only records attributed to their own principal ID.
The view paginates at 100 records and accepts an exact event-name filter, for example
`auth.login`, `vm.start`, `backend.sync`, or `backend.schedule`. Times are UTC.

Records capture time, stable requester ID and name snapshot, event, VM/backend target,
outcome, source IP, correlation/operation ID and sanitized details. All application
HTTP requests except static assets are recorded, including login success/failure,
logout, page reads, backend wizard steps, denied requests and schedule changes.
Worker events record queue execution, provider result and sync outcomes. CLI local
account creation, directory configuration and successful directory imports identify
their actor as `operator-cli`; named OS/operator attribution requires deployment
identity integration. Source IP is the direct peer; forwarded headers are not trusted
without an explicitly configured trusted proxy.

No request bodies, passwords, encryption keys, session cookies or raw provider errors
are logged. Audits have no edit/delete web endpoint; ORM updates and deletes are
blocked. This is application-level append-only protection, not protection from a
database owner. Production requires restricted DB roles, backups and export to an
immutable external log sink. Retention/export tooling is not implemented yet.

The current web login is the injected target account. A shared injected Custos
account remains a shared requester; per-person attribution requires individual
accounts or validated correlation with CyberArk session identity.

Reference: [VMware VM operation semantics](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.VirtualMachine.html).
