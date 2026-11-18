# Temporary-access AWS scans

The public entry point is `/sign-in` (also available at `/scan`). It connects an AWS role session for one scan. No LytaScan user account, organization, Cognito configuration, persistent cross-account trust, or operator AWS CLI login is required.

## Run a scan

1. In AWS, select a role with read-only audit permissions. The [rule catalog](check-catalog.md) lists the reads needed for each rule. IAM Identity Center users can choose **Command line or programmatic access** for that role. Alternatively, generate a short-lived STS assumed-role session using your own AWS tooling. Only temporary `ASIA…` credentials with a secret access key and session token are accepted. AWS account passwords, root credentials, and long-lived `AKIA…` keys are not supported.
2. Enter those three values and select one to six AWS commercial regions. Confirm that you chose a read-only role. Optionally enter the recipient email before connecting.
3. Click **Connect AWS**. The website uses `sts:GetCallerIdentity` to verify the account and assumed-role identity. This verifies identity, not the role’s IAM policy. The scanner separately blocks write operations at its SDK boundary.
4. Click **Run scan**. All 61 rules in the current registry run for their applicable global or selected regional scopes. At most two scope requests run at a time. The page displays scope progress, findings, and incomplete checks. Missing permissions and unsupported reads remain unavailable results; they do not count as passing checks.
5. Download JSON or CSV, or print/save the report as PDF. JSON includes findings, remediation, scope outcomes and coverage. CSV escapes formula-leading content for spreadsheet safety. Optional report email uses Resend and includes a JSON attachment.
6. Temporary credential references clear after the scan finishes. **Sign out & disconnect** also clears the report, identity, email, and input fields. Download first if you want to retain the report. Running another scan requires reconnecting with credentials.

## Access lifetime

Credentials are sent only in HTTPS POST bodies to the website’s Python function. They are not written to application storage, cookies, browser storage, query strings, a database, or logs. Each request constructs an explicit AWS SDK session from the submitted temporary credentials; there is no fallback to an operator profile or function execution identity. The scanner permits only read operations and STS identity lookup, and closes its clients before returning.

Disconnect stops the browser from dispatching additional scopes, waits for already dispatched requests to settle, and clears application-held credential references and report data. Closing the tab likewise stops new dispatches; requests already accepted by the server may finish. Disconnect does not revoke the underlying AWS STS credentials. Those expire on the AWS schedule; revoking role sessions through IAM is an AWS administrative action outside this read-only scanner. See [AWS temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) and [role-session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html).

## Email delivery

Production settings are server-only:

| Setting | Purpose |
| --- | --- |
| `RESEND_API_KEY` | Resend sending API key, stored as a Vercel Secret. |
| `REPORT_FROM_EMAIL` | Sender on a verified Resend domain; current sender is `lytascan@lytaworks.com`. |
| `SESSION_REPORT_SECRET` | Random private signing key of at least 32 characters, stored as a Vercel Secret and shared by the Python and Next.js functions. |

After identity verification, the Python function can issue an expiring email capability bound to the AWS account and requested recipient. The Next.js email endpoint validates that capability, account and recipient; it sends a fixed, escaped report template and a credential-free JSON attachment. Requests are bounded, provider retries use an idempotency key, and the sender key is never returned to the browser. Provider failures do not erase the downloadable report or claim successful delivery. The application requests delivery from Resend; inbox delivery remains subject to the recipient’s mail system.

The recipient is chosen before connecting and cannot be replaced using that capability. Email contains AWS resource identifiers and findings, so enter the intended recipient. When email is unconfigured, the page still provides downloads and a clearly labeled email draft requiring the user to attach a downloaded report and send it themselves.

## Hosting and limits

The existing Vercel project root is `web`. `web/api/scan.py` runs under the Python runtime and `web/app/api/report-email/route.ts` runs under Next.js. `web/requirements.txt` pins the Python AWS SDK. `web/vercel.json` includes the scanner runtime archive and gives each scope function up to 300 seconds.

The runtime archive is generated from the canonical scanner source and `api/ephemeral.py`; it is not a second hand-written scanner. Generate it after backend changes:

```powershell
.venv/Scripts/python.exe scripts/build_session_runtime.py
.venv/Scripts/python.exe scripts/build_session_runtime.py --check
```

Commit `web/scan-runtime.zip` and its manifest with source changes. Python CI and the Node-only frontend build check reject stale archives. Packaging tests import the archive outside the checkout and discover all 61 checks.

The function bounds request size, region count, AWS calls, elapsed scope time and finding count. A large or slow account can produce an explicitly incomplete scope. AWS API reads can incur AWS charges, and hosting limits still apply. The scanner does not change AWS resources or issue replacement credentials. A session report is a snapshot of the selected regions; the saved demo and the optional persistent organization lifecycle are separate workflows.

## Verification without a local server

Run Python tests, frontend unit tests/lint, and the production build. No development server is needed. After deployment, `GET /api/scan` must return the current 61-check registry and regions. Invalid POST requests must return sanitized errors with no-store headers. Test email transport with mocked provider responses; real customer credentials are never needed in CI. An actual end-to-end AWS scan requires the account owner to supply valid temporary role credentials in the deployed page.
