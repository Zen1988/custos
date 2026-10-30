<div align="center">
  <img src="branding/custos-logo-light.svg" alt="CUSTOS — Secure Infrastructure Access" width="440">

  # CUSTOS
  **Secure Infrastructure Access**

  *Infrastructure access, without infrastructure exposure.*

  **Status:** Design / UI prototype · **License:** To be decided
</div>

---

## Why Custos exists

A project team may need to **open a VM console, start a VM, stop a VM, or create a snapshot**. None of these everyday operations necessarily requires exposing the full vCenter or Nutanix Prism Central administration interface to that team.

Direct access to a virtualization management platform can expose users to more inventory, interfaces, privileges, and administrative functions than their work requires. Misconfigured roles, accidental privilege grants, compromised credentials, and vulnerabilities in management interfaces can increase the impact of that exposure.

**Custos deliberately offers only four operations.** Its value lies not in providing an elaborate interface, but in placing a tightly controlled authorization and integration boundary between project users and powerful virtualization management systems.

> A simple portal at the edge. A powerful management plane kept behind it.

Custos is a standalone product; it does not require TESSERA to operate. Future integration with ITSM/governance systems can be added without making them a dependency for normal console and VM actions.

## A practical security use case

Consider a project whose engineers need console access when a guest OS network configuration fails. Directly allowing those engineers to reach vCenter or Prism Central expands the set of users and endpoints that can interact with the management plane.

Custos provides an alternate network pattern:

```text
  PROJECT / USER NETWORK                         RESTRICTED MANAGEMENT NETWORK
  ┌──────────────────────────┐                   ┌─────────────────────────────┐
  │ Project users            │                   │ vCenter + ESXi              │
  │ Browser + corporate SSO  │                   │ Prism Central + AHV         │
  └─────────────┬────────────┘                   └─────────────▲───────────────┘
                │ HTTPS 443                                    │
                ▼                                              │ Allowlisted API /
     ┌─────────────────────────┐                               │ console endpoints
     │ Firewall / WAF / Ingress│                               │
     │ Only approved user path │                               │
     └────────────┬────────────┘                               │
                  │                                            │
                  ▼                                            │
     ┌─────────────────────────┐                   ┌───────────┴─────────────┐
     │ CUSTOS web + API        │                   │ CUSTOS integration      │
     │ SSO • VM entitlements   │  Authorized work │ gateway + console broker│
     │ policy • audit          ├──────────────────►│ scoped backend accounts │
     └─────────────────────────┘                   └─────────────────────────┘

  NO project-user route to vCenter / ESXi / Prism / AHV management endpoints.
```

**What this achieves:**

- Project users authenticate to **Custos**, not to the hypervisor management UI.
- The firewall allows user access to the Custos frontend, **not general access to vCenter or Prism Central**.
- Backend credentials stay server-side; project users do not receive or reuse them.
- Each action is checked against the specific user's project, VM, action permission, and applicable policy.
- The gateway can reach only the explicitly required provider API and console endpoints.
- Virtual console access can remain available when **guest network connectivity** is broken, provided the management plane and the console broker are healthy.
- Audit evidence identifies who requested which action against which VM and whether it succeeded.

**Important limitations:** Encryption alone does not enforce least privilege. An API service account with broad permissions, a broken authorization check, or an unsafe console proxy can still create a serious exposure. Network isolation, independently enforced authorization, credential isolation, and tightly scoped vendor permissions are mandatory. Console access may enable sensitive guest-level interaction; it is not equivalent to harmless read-only viewing.

## Scope: only four user-facing actions

| Action | Behavior | Required safeguards |
|---|---|---|
| **Console** | Open an interactive VM console through a controlled broker | VM-specific entitlement; ephemeral session authorization; guest-level security considerations |
| **Start** | Power on an authorized VM | Verify current state, authorization, policy, and provider result |
| **Stop** | Prefer graceful guest OS shutdown where supported | Verify tools/guest capability; forced power-off is a separate restricted decision |
| **Create Snapshot** | Request a VM snapshot | Policy limits, allowed VM state, capacity checks, retention and cleanup ownership |

Read-only inventory details and operation status support these functions. Custos **does not** offer general VM administration, privilege management, VM deletion, resource resizing, network configuration, ISO mounting, virtual media access, or arbitrary provider API calls.

> Snapshots are not backups. Snapshot expiry and cleanup require separately authorized backend maintenance; Custos v1 does not expose a delete-snapshot button to project users.

## Security model

The core security decision is **user + project + VM + action + policy**. Every factor must allow an operation, and the backend must verify it **at action execution time**, not merely when rendering buttons.

1. **Identity separation:** users log into Custos through an enterprise identity provider (planned OIDC/SSO; MFA enforced by policy). They are not granted direct hypervisor management credentials as part of this workflow.
2. **Object-level authorization:** a Project A user must never access Project B's VM by changing a URL, object identifier, or WebSocket request.
3. **Least-privilege provider identities:** use narrowly scoped read, power, snapshot, and console permissions wherever supported. A service account is **not automatically API-only**; some vendor accounts may also support interactive login and therefore need network and identity restrictions.
4. **Dedicated integration boundary:** no browser-to-hypervisor management connection; provider API destinations and operations are allowlisted.
5. **No arbitrary proxy:** the gateway cannot accept caller-supplied management URLs, uncontrolled API routes, or unsupported commands.
6. **Console brokering:** vendor tickets/tokens and privileged sessions remain behind Custos. Console access is isolated, expires, and is checked on establishment and revocation.
7. **Operation safety:** asynchronous jobs use durable state, idempotency, per-VM concurrency controls, and provider-side outcome verification.
8. **Auditability:** store requester, project, VM, operation, authorization decision, timestamp, provider task reference, result, and correlation ID; protect logs from unauthorized modification.
9. **Secret security:** no credentials in source control, HTML, JavaScript, error responses, or browser sessions. Use a secret manager and rotate credentials.
10. **Fail closed:** unavailable identity, entitlement, or policy dependencies must not result in permissive access.

Privileged infrastructure administrators retain a separate, strongly governed break-glass path. Custos is **not** a substitute for hypervisor patching, vendor RBAC, guest OS security, firewalls, or privileged-access management.

## Architecture

Custos is designed as a **Python modular monolith** with an independently isolated console gateway, not a collection of unnecessary microservices.

```text
Browser / HTML5
  │
  ▼
Python web + API (Flask, Jinja2)
  ├─ Identity / SSO
  ├─ Project + VM entitlements
  ├─ Action policy / audit
  ├─ VM inventory view
  └─ Operation submission
       │
       ├── PostgreSQL: identities, mappings, jobs, audit
       │
       ▼
  Worker + Provider interface
       ├── VMware adapter → vCenter APIs
       └── Nutanix adapter → Prism Central APIs

Separate console gateway (Python ASGI/WebSockets)
       ├── VMware console protocol integration
       └── Nutanix console protocol integration
```

The adapters implement a consistent internal interface, while accommodating provider-specific APIs, permissions, operation semantics and version limitations. The architecture **does not assume** VMware and Nutanix share identical console protocols or snapshot behavior.

### Technology choices

| Layer | Choice |
|---|---|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3, vanilla JavaScript, Jinja2 |
| Production database | PostgreSQL |
| Local single-process prototype | SQLite |
| Models / migrations (planned) | SQLAlchemy / Alembic |
| Console gateway (planned) | Python ASGI / WebSocket service |
| Deployment (planned) | Containers and Helm on Kubernetes |
| Tests (planned) | pytest, integration tests, authorization-negative tests |

**Database note:** SQLite is appropriate for a local, single-instance prototype. PostgreSQL is the intended production database for concurrent sessions, multi-replica services, durable operations, and audit history. Do not share one SQLite database file among independent Kubernetes writers.

### Suggested Git repository structure

```text
custos/
├── README.md
├── pyproject.toml
├── .env.example
├── .github/workflows/
├── branding/                # Logos, icons, brand tokens
├── src/custos/
│   ├── main.py
│   ├── api/                 # HTTP endpoints and request schemas
│   ├── core/                # Identity, authorization, entitlement, policy, audit
│   ├── services/            # Inventory, power, snapshots, operations
│   ├── providers/
│   │   ├── base.py
│   │   ├── vmware/
│   │   └── nutanix/
│   ├── database/            # Models, sessions, repositories
│   ├── workers/             # Durable execution
│   └── web/
│       ├── templates/      # HTML5 / Jinja2
│       └── static/         # CSS, JS, icons
├── console_gateway/        # Isolated broker implementation
├── migrations/
├── deployments/helm/custos/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
└── docs/
    ├── security-model.md
    ├── architecture.md
    ├── provider-compatibility.md
    └── deployment.md
```

This tree is the **target repository layout**, not a claim that all components have already been implemented.

## Local UI prototype

The separately distributed Custos UI starter currently has static/mock VM inventory and a Flask page. It does **not** authenticate, connect to vCenter/Prism, start or stop VMs, issue console sessions, write an audit database, or enforce access control. **Never expose the prototype as a live project-user portal.**

From the extracted prototype package:

```bash
cd custos-brand-kit/web
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:8080**. The development server binds to localhost by default.

When the new repository is initialized, migrate the prototype's templates and assets into `src/custos/web/` and `branding/`.

## Implementation roadmap

- [x] Product concept and four-action scope
- [x] Branding and standalone visual UI prototype
- [ ] Repository/bootstrap, packaging, tests and CI checks
- [ ] OIDC SSO, project membership and VM-specific entitlements
- [ ] PostgreSQL models and migration framework
- [ ] Read-only VMware and Nutanix inventory adapters
- [ ] Controlled Start and Stop operations
- [ ] Controlled snapshot creation, limits and lifecycle cleanup
- [ ] VMware/Nutanix console protocol integration through an isolated broker
- [ ] Security validation: cross-project access, credential isolation, WebSocket authorization, SSRF, CSRF, audit integrity
- [ ] Production Helm deployment, network policy and secret management

## Acceptance criteria before production

Custos is **not production-ready** until security tests demonstrate that:

- Project users cannot directly access hypervisor management endpoints through the approved user network path.
- No user can see or operate on an unauthorized VM through API or WebSocket manipulation.
- Only allowed operations reach the provider adapter, under a permission-scoped backend identity.
- Provider credentials and console session secrets never reach the browser.
- A compromised or malformed frontend request cannot turn the integration gateway into an unrestricted proxy.
- Snapshot limits, shutdown behavior, audit storage and failure recovery behave as designed.
- Console routes and permissions have been validated on the actual deployed vCenter/ESXi and Prism Central/AHV versions.

## Guiding principle

> **Expose the task, not the management plane.**
>
> Four ordinary buttons do not justify giving every project engineer the keys to the entire virtualization environment.

CUSTOS exists to make routine infrastructure interaction simple for authorized users—and deliberately difficult to misuse beyond its limited purpose.
