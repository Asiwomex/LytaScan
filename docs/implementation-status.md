# LytaScan implementation status

The public product includes a temporary-access AWS session scanner, plus the saved-data demo. The M0–M2 organization platform remains a separate optional deployment; organization scans in its local preview use simulated results.

| Surface | Implemented |
| --- | --- |
| Temporary-access session scanner | Public `/sign-in` and `/scan` accept temporary read-only AWS role credentials, verify identity, evaluate the existing 61-rule registry by scope, show progress and findings, and export JSON/CSV or print. Credentials clear after execution; disconnect drains dispatched checks and clears page data. No Cognito dependency or operator AWS credentials. |
| Report email | Optional Resend delivery using a verified sender. An expiring, signed capability binds delivery to the inspected AWS account and chosen email. Reports exclude credentials; failed email delivery leaves downloads available. |
| Homepage and demo | Interactive sample review, saved scan trend, pillar and breakdown filters, searchable and sortable findings, and remediation details. The homepage also lists the current check catalog. |
| Organizations and access | Local registration and email verification, organization creation and switching, invitations, member role and account-grant editing, member removal, and ownership transfer. Hosted identity uses Cognito and requires the production API URL, Cognito domain, and client ID at build time. The published demo alone does not enable client accounts. |
| AWS connections | Read-only role setup with a connection-specific external ID, role verification, connection quotas, and disconnection with scan-history cleanup. The local adapter simulates verification. |
| Scan jobs | Full, quick, and pillar scans. Per-rule and per-region progress, results, cancellation and scoped retry where applicable. Private legacy history supports dry-run preview, import checkpoints, and rollback. |
| Scanner | 61 rules across all six AWS Well-Architected pillars, v2 scoring and coverage, unavailable-result reporting, a generated check catalog, and JSON CLI reports. |
| Finding lifecycle | Workflow status, comments, audit history, scoped verification, and time-limited exceptions. A confirmed pass or authoritative inventory absence can resolve a finding. A later failure can reopen it. |

## Verification and scope

- The local browser preview and automated suite exercise simulated workflows. The saved public demo, simulated organization fixture, and hosted AWS integration use separate data paths.
- Session-scanner behavior is covered with explicit mocked AWS identities and responses, request-boundary tests, credential/error redaction checks, queue-drain tests, report-export tests, signed-email tests, and deployment-archive checks. Deployment verification probes the real Python endpoint and rejects invalid credentials without creating a scan. A successful full scan requires a visitor’s valid temporary AWS role credentials.
- The optional organization platform still needs separate hosted validation for Cognito, role setup, queues, and stored lifecycle results. These dependencies do not gate the public session scanner.
- M3–M7 are outside the current scope. Standalone FinOps, inventory and topology, drift and remediation automation, compliance reporting, and operations integrations are deferred. Inventory used for finding resolution is part of M2.

See the [session scan guide](session-scans.md), the [local onboarding and workspace guide](m1-onboarding.md), the [generated rule catalog](check-catalog.md), the [design guide](../DESIGN.md), and the [upgrade baseline](upgrade-baseline.md).
