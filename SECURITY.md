# Security Policy

## Scope and safe use

Cyber SOC Agent is an educational, local-first incident-analysis and response-simulation project. It is **not production-ready** and currently has no authentication or role-based access control. Do not expose the API or dashboard to the public internet or untrusted networks.

Response actions are simulation-only and require an explicit approval step. Do not contribute real host, network, firewall, identity-provider, or session-control integrations without a separately reviewed project redesign.

See [the detailed security model and known gaps](docs/security.md).

## Reporting a vulnerability

Please do not disclose credentials, personal data, or exploit details in a public issue. Contact the repository maintainer privately through GitHub and include:
- Affected component and version/commit
- Impact and realistic attack prerequisites
- Safe reproduction steps or a minimal proof of concept
- Any suggested mitigation

Do not test against systems you do not own or have explicit permission to assess.
