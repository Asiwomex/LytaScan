# M1 onboarding quickstart

Use two terminals. From the repository root on Windows, set up the Python environment and start the local API.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"
.venv/Scripts/python.exe -m uvicorn api.local:app --host 127.0.0.1 --port 8000
```

In the second terminal, start the frontend.

```powershell
cd web
pnpm install --frozen-lockfile
$env:NEXT_PUBLIC_LOCAL_ONBOARDING = "true"
pnpm dev --hostname 127.0.0.1 --port 3000
```

On macOS or Linux, use `.venv/bin/python` and start the web server with `NEXT_PUBLIC_LOCAL_ONBOARDING=true pnpm dev --hostname 127.0.0.1 --port 3000`.

1. Open [local registration](http://127.0.0.1:3000/sign-up). Use an address ending in `@example.test` and a fictional password of at least 12 characters.
2. Enter the verification code displayed in the preview and sign in.
3. Create an organization, select **Connect an account**, and enter account ID `111122223333`. Select a region and approve the read-only metadata check.
4. Copy the sample role ARN into **Role ARN** and select **Verify connection**. The preview simulates success for that account ID and a role denial for other IDs.

The local API keeps its identities, sessions, organizations and connections in memory. Restarting it clears them. It makes zero AWS requests. The local entry point and authentication adapter are separate from the Lambda handler. The frontend local flag applies only to development builds.

## AWS configuration for a future approved deployment

- Configure the existing Cognito app and API URL. To open registration, set the Terraform variable `enable_registration` and the frontend variable `NEXT_PUBLIC_ENABLE_REGISTRATION` to true. Cognito handles passwords, email verification, recovery and MFA. The existing `/account` callback remains in use.
- Set `verification_allowed_accounts` to the approved commercial AWS account IDs for a restricted beta. An empty list leaves the account allowlist off.
- The organization API authorizes the Cognito access-token subject against a strongly consistent membership lookup. Owner and administrator are the roles allowed to manage connections. Organization creation and its initial owner membership are written together. The three-connection quota and membership check are part of the connection transaction.
- Create the named CloudFormation role through the setup link and use its RoleArn output. The scanner verifies the exact generated ARN, checks the STS account and assumed role, confirms both absent and incorrect external IDs are rejected, then probes IAM and EC2 metadata. The verification session policy is scoped to those probes. A verified connection records a point-in-time result.
- The new records are additive. Legacy invited users can still use the existing account workflow. Organization history is populated through the explicit import workflow below.

The AWS path still needs an operator-approved sandbox test for Cognito email delivery, successful role verification, denied access, and trust-policy changes.

## Team, scans and legacy history

- In **Organizations**, an owner or administrator can create a team invitation and share the link with the intended recipient. The recipient signs in with the invited verified email. Links expire after 24 hours and can be revoked while pending. Scoped viewer, engineer and security analyst invites grant one connection. Only owners can invite administrators. Cognito provides the verified address in hosted mode. Invitations are shared manually.
- **Run scan** queues a scan for the verified connection's configured region and global checks. The account can have one active scan, the organization two, and the account can request three per UTC day. The worker checks access and connection identity before claiming a job and again before publishing results. Cancelled jobs stop publication. AWS calls already in progress may still finish. Job leases allow recovery after a worker exits, and jobs that exceed the queue deadline display as expired.
- **Preview legacy history** is a read-only dry run for the signed-in owner. The source is that user's private legacy history for the same verified AWS account. Import one scan at a time. Each scan has a stable checkpoint and retains its original expiry. **Roll back import** immediately hides the organization copy. Unreferenced copies expire automatically and source history stays intact. Public scrubbed reports are outside the migration scope.
- In the local preview, **Load sample legacy history** creates fictional source data for the sample account. Scan jobs also use fictional results. Local verification covers the workflow from account setup to import, rollback and team acceptance. Hosted delivery through SQS and Cognito's user-info endpoint still require sandbox verification.
