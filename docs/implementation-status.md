# Pillarscan 2.0 implementation status

| Requirement | Milestone | Module | Status and verification |
| --- | --- | --- | --- |
| Baseline | M0 | Repository, CI | Recorded in [upgrade-baseline.md](upgrade-baseline.md). Scanner and API tests, Terraform validation, frontend lint, frontend tests and TypeScript passed. |
| UI | M1 | Next.js | Standalone demo and local onboarding are implemented. Browser checks covered demo navigation, findings search and details, reset and theme persistence, then registration through simulated verification. |
| CORE-01 | M1 | Cognito, organization API, DynamoDB | Opt-in registration and organization creation. Team invitations support role selection, account grants for scoped roles, one-time acceptance by the verified email, expiry and revocation. Membership editing, owner transfer and multiple grants per member remain open. |
| CORE-02 | M1 | Connection API, scanner Lambda | Connection-specific role and external ID, read-only consent, atomic connection quota, optional allowlist and verification cooldown. The AWS adapter checks STS identity, requires a correct external ID and probes IAM and EC2 metadata reads. Tests use mocks and the local preview simulates the outcome. Live verification is pending. |
| CORE-03 / CORE-04 | M1 | IAM, worker and storage | Verification sessions are limited to the three required AWS calls. Organization scan jobs have conditional queue and worker claims, account and daily quotas, cancellation, and scoped results. Legacy history supports a dry run, per-scan checkpoints and rollback. Versioned module policies and organization connection removal remain open. |
| SCAN | M2 | Scanner, findings | Pending. Legacy 22-check scanner available. |
| FIN | M3 | Cost collectors and UI | Pending. |
| INV | M4 | Inventory, topology | Pending. |
| DRIFT / FIX | M5 | Snapshots, remediation | Pending. |
| COMP | M6 | Compliance, reporting | Pending. |
| OPS | M7 | Alerts, integrations, admin, CI | Pending. Sandbox and public-beta release gates remain pending. |

## Local preview

Run `pnpm dev --hostname 127.0.0.1` from `web` and open [the demo](http://127.0.0.1:3000/demo). The demo reads the fictional fixture shipped in the repo and needs no AWS credentials or backend configuration. The landing page continues to serve the embedded legacy demo at `/#demo`. For registration and verification, follow the [local onboarding quickstart](m1-onboarding.md).

The site uses local font fallbacks and builds with Webpack and Tailwind PostCSS. The development server uses Turbopack.
