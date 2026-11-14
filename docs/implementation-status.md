# LytaScan implementation status

The current scope is the local M0–M2 product. The public demo uses saved data. Organization scans in the local preview use simulated AWS results.

| Surface | Implemented |
| --- | --- |
| Homepage and demo | Interactive sample review, saved scan trend, pillar and breakdown filters, searchable and sortable findings, and remediation details. The homepage also lists the current check catalog. |
| Organizations and access | Local registration and email verification, organization creation and switching, invitations, member role and account-grant editing, member removal, and ownership transfer. Hosted identity is configured through Cognito. |
| AWS connections | Read-only role setup with a connection-specific external ID, role verification, connection quotas, and disconnection with scan-history cleanup. The local adapter simulates verification. |
| Scan jobs | Full, quick, and pillar scans. Per-rule and per-region progress, results, cancellation and scoped retry where applicable. Private legacy history supports dry-run preview, import checkpoints, and rollback. |
| Scanner | 61 rules across all six AWS Well-Architected pillars, v2 scoring and coverage, unavailable-result reporting, a generated check catalog, and JSON CLI reports. |
| Finding lifecycle | Workflow status, comments, audit history, scoped verification, and time-limited exceptions. A confirmed pass or authoritative inventory absence can resolve a finding. A later failure can reopen it. |

## Verification and scope

- The local browser preview and automated suite exercise simulated workflows. The saved public demo, simulated organization fixture, and hosted AWS integration use separate data paths.
- Hosted validation is deferred. This includes Cognito email delivery and authentication, AWS role verification, queue delivery, live read permissions and versioned IAM module policies, runtime, and cost. This status does not certify a hosted deployment.
- M3–M7 are outside the current scope. Standalone FinOps, inventory and topology, drift and remediation automation, compliance reporting, and operations integrations are deferred. Inventory used for finding resolution is part of M2.

See the [local onboarding and workspace guide](m1-onboarding.md), the [generated rule catalog](check-catalog.md), the [design guide](../DESIGN.md), and the [upgrade baseline](upgrade-baseline.md).
