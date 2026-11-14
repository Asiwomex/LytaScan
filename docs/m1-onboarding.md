# Local onboarding and workspace guide

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
pnpm dev --hostname 127.0.0.1 --port 3100
```

On macOS or Linux, use `.venv/bin/python` and start the web server with `NEXT_PUBLIC_LOCAL_ONBOARDING=true pnpm dev --hostname 127.0.0.1 --port 3100`.

1. Open [local registration](http://127.0.0.1:3100/sign-up). Use an address ending in `@example.test` and a fictional password of at least 12 characters.
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
- **Team members** lets owners and administrators change roles, edit account grants, and remove members. Only the owner can manage administrator membership and transfer ownership. A transfer promotes an active administrator and changes the previous owner to administrator in the same transaction. Members from before the directory index was added are listed through their accepted invite while that record is retained.
- **Disconnect** immediately revokes LytaScan's use of that connection. The worker cleans up its organization scan history, including published imports. A scan already running cannot publish after the connection is removed. If enqueueing cleanup fails, use **Retry scan history cleanup**. In hosted mode, delete the named CloudFormation stack separately to revoke the IAM role in AWS. A new connection to the same account requires verification with a new role.
- In the local preview, **Load sample legacy history** creates fictional source data for the sample account. Scan jobs also use fictional results. Local verification covers the workflow from account setup to import, rollback and team acceptance. Hosted delivery through SQS and Cognito's user-info endpoint still require sandbox verification.

Hosted references include the [Cognito access-token and user-info contract](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html) and [Lambda queue visibility and retries](https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-configure.html).

### Workspace access

| Role | Current access |
| --- | --- |
| Owner | Organization-wide scan and finding access, connection and team management, legacy scan import and rollback, and ownership transfer. |
| Administrator | Organization-wide scan and finding access, connection management, and management of scoped members. Only an owner can manage administrator membership. |
| Engineer | View and run scans, retry scopes and verify findings, and update finding workflows on the granted connection. |
| Security analyst | View scans and update finding workflows on the granted connection. |
| Viewer | View scans and tracked findings on the granted connection. |
| Finance analyst | Membership with a connection grant. The current workspace has no cost views for this role. |

Suppression, risk acceptance, and false-positive decisions require a reason and an expiry within 90 days. The technical outcome stays visible independently of the workflow decision.

## M2 scanner preview

```powershell
.venv/Scripts/python.exe -m scanner --catalog
.venv/Scripts/python.exe -m scanner --profile <aws-profile> --report-version 2 --regions us-east-1 --out findings.json
```

The catalog command works without AWS credentials. Organization scan results show the same six-pillar assessment and coverage contract. The default CLI report and legacy history keep their original scoring. The v2 score averages evaluated pillars and separately displays unavailable evaluations and planned versus completed scopes.

The catalog contains 61 rules: 17 security, 12 reliability, 7 cost, 13 operational excellence, 10 performance efficiency, and 2 sustainability. The JSON catalog records read permissions and includes AWS references and applicability for the new checks. The customer audit role may need extra read permissions for optional services, including `codepipeline:ListPipelineExecutions`. Metric rules use bounded CloudWatch queries, which can incur AWS request charges in a live account. [CloudWatch API pricing](https://aws.amazon.com/cloudwatch/pricing/)

In **Organizations**, run a scan and open **Tracked findings**. Finding records stay attached to the connection and resource across scans. A failed check opens or reopens a finding. A confirmed pass in a complete scope resolves it. An absent evaluation or incomplete read leaves the issue unresolved. The workspace supports acknowledgment, work in progress, comments, and time-limited suppression, risk acceptance and false-positive decisions. Verification evaluates one rule within the connection's scope and keeps the selected resource result. The local fixture simulates a pass for verification and restores the original failure on the next full scan.

The **Scan jobs** table shows queued, running, and settled rule scopes. Open **Progress** to inspect the rule and region, evaluation totals, timing, and unavailable reasons. Retry an incomplete scope as a separate job. Quick scans run a small security subset. Pillar scans run that pillar only. The full scan also inventories resource types with unresolved findings when an authoritative collector is available.

Deletion resolution requires a complete inventory for the same account, resource type, and region, plus a complete evaluation of the relevant rule. Failed or truncated inventories and unrecognized resource identities cannot close findings. Account-level conditions and resources without an authoritative collector remain open until a confirmed pass. The current scope covers inventory-backed finding resolution. Standalone inventory, cost, compliance, and drift workflows are deferred.

The local fixture includes an EC2 instance that fails the IMDSv2 rule on its first full scan. On the second full scan the instance is absent from a complete inventory, so the finding timeline records **Resource deleted**.

The first new rules assess [CloudWatch metric alarm actions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarms.html), [optional EC2 EBS optimization](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html), and [S3 lifecycle cleanup for incomplete multipart uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html). The performance and sustainability checks are configuration indicators. They do not estimate workload demand or emissions.
