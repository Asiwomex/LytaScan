# Pillarscan 2.0 upgrade baseline

The upgrade started from a clean `main` at `d7e3467` on November 13, 2026. The attached Pillarscan 2.0 specification defines the upgrade direction.

## Existing entry points and contracts

| Area | Baseline |
| --- | --- |
| Web | Next.js App Router, TypeScript, Tailwind and pnpm. `/` contains the landing and embedded demo, including a scrubbed project-account view. `/account` uses invite-only Cognito when configured and shows a paused state otherwise. |
| Public API | `GET /health`, `GET /scans` and `GET /scans/{scan_id}` (including `latest`). |
| Private API | `GET/POST /me/accounts`, `DELETE /me/accounts/{aws_account_id}`, `GET/POST /me/accounts/{aws_account_id}/scans`, and `GET /me/accounts/{aws_account_id}/scans/{scan_id}`. API Gateway supplies the verified Cognito subject. |
| CLI | `python -m scanner` accepts a profile, optional role ARN and external ID, regions and output path. It emits scan metadata and findings. The engine discovers 22 checks across security, reliability and cost. |
| Findings | Each evaluation has a check ID, title, pillar, severity, pass/fail/error outcome, resource ARN/type, region, account ID, description, remediation and timestamp. Scan summaries and evaluations live in DynamoDB. Connected accounts are scoped to Cognito user plus AWS account ID. |
| AWS | Terraform defines the API and scanner Lambdas, API Gateway, Cognito, DynamoDB, SQS, a daily schedule and monitoring. The platform uses encrypted S3 remote state with locking. CloudFormation creates the external-ID audit role with AWS SecurityAudit and ViewOnlyAccess policies. |
| Dependencies and CI | Python 3.12+, boto3, FastAPI/Mangum and pytest/Moto. The web and Terraform provider lockfiles are tracked. CI covers Python, CloudFormation lint, Terraform formatting/validation, and frontend lint/tests/build. |

## Baseline verification

- `.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider tests/scanner` passed 125 tests.
- `pnpm test` from `web` passed 26 tests. `pnpm build` failed fetching Instrument Sans and JetBrains Mono from Google Fonts.
- `.venv/Scripts/python.exe -m pytest -q -p no:cacheprovider tests/api` passed 16 tests with local loopback networking available. The initial run stalled while Windows tried to open an asyncio socket.
- `terraform fmt -check -recursive infra` and `terraform validate` in bootstrap, platform and bait passed once provider processes could communicate locally.

## Compatibility and migration approach

Keep the CLI JSON, existing routes and legacy sample demo compatible. Add versioned API and storage contracts alongside the legacy ones. Introduce explicit organization membership and connection ownership before exposing private data through new routes. Review and test the mapping of each legacy connection to its owner's organization before moving records. Keep the legacy reader available through the migration, validate ownership and counts, then switch traffic with a rollback path.
