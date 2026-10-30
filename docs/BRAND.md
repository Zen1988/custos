# CUSTOS — Brand guidelines (v0.1)

**Name:** Custos (Latin: guardian/keeper)  
**Descriptor:** Secure Infrastructure Access  
**Tagline:** Infrastructure access, without infrastructure exposure.

## Identity
- Midnight navy `#0B1F31` is the primary backdrop.
- Teal `#14B8A6` indicates trust and control; mint `#6EE7DD` adds contrast.
- Use system UI sans-serif typography; no external font is required.
- Use dark logo on navy, light logo on light surfaces.
- Do not stretch logos or distort shield shape; retain at least 16px clear space.

## Scope
Console, Start, Stop (graceful first), Create Snapshot.
No delete, hardware reconfiguration, unrestricted API execution or management UI pass-through.

## Security disclosure
The preview UI is **mock-only** and implements no live hypervisor operations or authentication. Never use client-side permission checks alone; enforce per-VM, per-action authorization server-side. Console access requires a server-side broker, network isolation and provider-specific validation.
