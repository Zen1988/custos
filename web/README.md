# Custos web development

The web app requires a local or synced directory account and session secret. Run the CLI and web
server from the repository root to use the same database path.

See [identity setup](../docs/identity-setup.md) for installation, database creation,
local accounts, directory sync, HTTPS and CyberArk PSM connector configuration.

The workspace shows only authorized, fresh VM records from the Custos database.
PSM can submit injected credentials to `/login` (local) or
`/login/directory/<directory-id>` (AD/LDAP), then land directly on the workspace.
Scheduled backend inventory sync and Start/Stop/Reboot/Reset/snapshot actions require
the separate [background worker](../docs/operations-and-audit.md). The console broker
and production deployment remain pending.
