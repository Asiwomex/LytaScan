# LytaScan

[![CI](https://github.com/Asiwomex/LytaScan/actions/workflows/ci.yml/badge.svg)](https://github.com/Asiwomex/LytaScan/actions/workflows/ci.yml)

LytaScan is a read-only AWS posture scanner and review workspace. Its current registry contains **61 rules across the six AWS Well-Architected pillars**. Reports identify the affected resource and scope, explain the risk, and suggest a fix. When a rule cannot evaluate a scope, the report shows why and keeps coverage distinct from the posture score.

The public scan flow is **temporary AWS access → run 61 checks → download or email results → disconnect**. It works through the website’s Python function and does not require LytaScan registration or the separate Cognito/organization deployment. The demo and organization preview still use fictional data. The existing M0–M2 organization platform remains a separate, optional deployment.

## What you can use

| Surface | What it does |
| --- | --- |
| Homepage · `/` | Plays a guided review of a saved fictional scan through Inventory, Evaluate, Prioritize, and Verify. The embedded scan explorer includes account switching, trend views, an expandable breakdown, sortable and searchable findings, and a detail panel. The checks section lists all 61 rules. |
| Standalone demo · `/demo` | Opens a saved fictional report without signing in. Compare scan trends, narrow the findings table, open details and remediation guidance, and switch the demo theme. The saved fixture demonstrates the legacy report with 22 rules across Security, Reliability, and Cost. |
| Session scan · `/sign-in`, `/scan` | Enter temporary credentials from a read-only AWS role, select up to six regions, verify the AWS identity, then run all 61 checks with live scope progress. Download JSON/CSV, print the report, or optionally receive the report through Resend. Credentials clear after execution. Sign out clears the session and report. No LytaScan registration is required. |
| Optional organization onboarding · `/sign-up`, `/forgot-password` | Existing Cognito registration and password recovery for an independently configured organization platform. Without that platform configured, these routes redirect to the session scanner. |
| Workspace · `/organizations`, `/accounts/connect` | Create or switch organizations, invite team members, manage roles and account grants, and connect an AWS account for read-only verification. Owners can transfer ownership. Disconnect revokes LytaScan's use of the connection and starts scan history cleanup. Owners can preview, import, or roll back eligible private legacy scan history into the matching connection. |
| Scan jobs and findings · `/organizations` | Launch full, quick, or pillar scans, follow rule and region progress, retry an incomplete scope, cancel jobs, and review results. Tracked findings include evidence, comments, workflow history, time-limited exceptions, and targeted verification. |
| Legacy account · `/account` | Preserves the hosted organization sign-in callback when configured; otherwise opens the session scanner. |
| CLI · `python -m scanner` | Runs the scanner with an AWS profile or an assumed audit role, writes JSON, and exports the rule catalog without AWS credentials. |

See the [generated check catalog](docs/check-catalog.md) for rule scope and permissions. The JSON catalog also includes rule versions and applicability metadata. The [implementation status](docs/implementation-status.md) records the current scope and remaining validation. The [design guide](DESIGN.md) covers layout, responsive behavior, and the visual system.

### How findings change

A failed evaluation opens a tracked finding. A passing evaluation from a complete scope can resolve it. A full scan can also resolve it as **Resource deleted** when complete inventory confirms the resource is absent from the same account, type, and region. Missing permissions, incomplete scope coverage, or truncated inventory cannot confirm a resolution. A later failure reopens it.

The workflow state, such as **In progress** or **Suppressed**, is separate from the scanner's evaluation. Verification reruns the finding's specific rule for its connection and scope. LytaScan gives remediation guidance and does not change the AWS resource.

## Run locally

Use Python 3.12 or newer for the API and scanner, and Node.js 22 with pnpm for the web app.

In a terminal at the repository root:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"
.venv/Scripts/python.exe -m uvicorn api.local:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd web
pnpm install --frozen-lockfile
$env:NEXT_PUBLIC_LOCAL_ONBOARDING = "true"
pnpm dev --hostname 127.0.0.1 --port 3100
```

On macOS or Linux, use `.venv/bin/python` and start the frontend with `NEXT_PUBLIC_LOCAL_ONBOARDING=true pnpm dev --hostname 127.0.0.1 --port 3100`.

- Open the [homepage](http://127.0.0.1:3100/) or [standalone demo](http://127.0.0.1:3100/demo). Both can display saved data with only the web server running.
- To try the workspace, [create an account](http://127.0.0.1:3100/sign-up) with a fictional `@example.test` address and a fictional password of at least 12 characters. Enter the verification code shown in the preview, sign in, and create an organization.
- Connect sample account `111122223333`, copy the example role ARN from the setup page, and verify the connection. In the workspace, run a scan and open **Progress** and **Tracked findings**.

The local API keeps test users, sessions, and workspace records in memory. Restarting it clears those records. Local verification and scans are simulated. The localhost mode runs only with the development frontend. The [onboarding and scanner walkthrough](docs/m1-onboarding.md) covers member invitations, progress retries, finding verification, and legacy import.

## Use the scanner CLI

Print the current catalog without contacting AWS:

```powershell
.venv/Scripts/python.exe -m scanner --catalog
```

To use the expanded registry against an AWS account you manage, supply an authorized AWS profile and the regions you intend to review:

```powershell
.venv/Scripts/python.exe -m scanner --profile <aws-profile> --report-version 2 --regions us-east-1 --out findings.json
```

The default CLI report retains version 1 for compatibility. Version 2 adds the expanded registry, scope coverage, and pillar scores. The CLI uses the profile's permissions by default. To assume an existing read-only audit role, pass both `--role-arn` and `--external-id`. See the [CloudFormation role template](onboarding/pillarscan-role.yaml) and the [current catalog](docs/check-catalog.md) for permission requirements.

`findings.json` may contain real account IDs and ARNs. Keep it private. The repository includes a [scrubbing tool](scanner/scrub.py) and two saved fixtures in [sample-data](sample-data). The fictional fixture drives the guided review and demo. The project account fixture is a scrubbed saved scan. Metric-based rules can issue CloudWatch calls when run against AWS.

## Architecture and data boundaries

| Path | Components and data |
| --- | --- |
| Local preview | Next.js reads saved reports. The development-only FastAPI app uses simulated authentication, an in-memory DynamoDB mock, and fixture scans to exercise workspace flows. |
| Hosted configuration | Next.js uses Cognito sign-in and API Gateway. FastAPI authorizes organization requests by verified identity, membership, role, and connection grant. SQS hands work to the scanner Lambda. The worker assumes the connection's audit role with its external ID and stores results in DynamoDB. Terraform definitions live in [infra/platform](infra/platform). |
| Public and private reports | The public project history API serves scrubbed project reports. Legacy signed-in reports and organization results use separate, access-controlled routes and storage scopes. Public reports are excluded from legacy import. |
| Reporting and changes | Read-only AWS observations generate recommendations. Scan records, comments, memberships, and workflow decisions are application data. Removing a connection begins application cleanup. Removing the role itself requires removing the CloudFormation stack in the AWS account. |

The homepage exposes **Scan AWS**. Read the [session scan guide](docs/session-scans.md) for temporary credential setup, downloads, email delivery, disconnect behavior, deployment, and limits. The session scanner is independent of Cognito and the operator’s AWS CLI profile. The older organization workspace still follows the [organization onboarding guide](docs/m1-onboarding.md#enable-hosted-organization-access).

The hosted configuration uses `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_COGNITO_DOMAIN`, and `NEXT_PUBLIC_COGNITO_CLIENT_ID`. To enable hosted registration, set `NEXT_PUBLIC_ENABLE_REGISTRATION` and enable registration in Cognito. Operations references include the [onboarding guide](docs/m1-onboarding.md), [AWS infrastructure definitions](infra/platform), and [deployment and cleanup scripts](scripts). Running the localhost preview does not use those scripts.

## Verify changes

From the repository root:

```powershell
.venv/Scripts/python.exe scripts/build_session_runtime.py --check
.venv/Scripts/python.exe -m pytest
```

From `web`:

```powershell
pnpm lint
pnpm test
pnpm build
```

[GitHub Actions](.github/workflows/ci.yml) runs mocked AWS scanner and API tests, validates the CloudFormation role template and Terraform configuration, and runs frontend lint, tests, and build. Live AWS permissions, identity delivery, worker runtime, and cost still require sandbox validation.

LytaScan is an independent portfolio project by [Asiwome Boateng](https://asiwomex.vercel.app/). AWS and its service names are trademarks of Amazon.com, Inc. or its affiliates.
