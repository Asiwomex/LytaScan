import { createHmac, timingSafeEqual } from "node:crypto";
import { PILLARS, SEVERITIES, STATUSES, type Finding, type Pillar, type ScanReport } from "./findings";

export type EmailSettings = { apiKey: string; sender: string; signingSecret: string };
type EmailScope = { check_id: string; pillar: Pillar; region: string; status: "queued" | "running" | "complete" | "incomplete"; reason_codes?: string[] };
export type EmailReport = ScanReport & { scopes?: EmailScope[]; execution?: { source: "temporary_session"; stopped: boolean; settled_scopes: number } };
const MAX_SCOPES = 600;
const MAX_BYTES = 2_000_000;
const EMAIL = /^[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+$/;
const HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
const deliveries = new Map<string, { until: number; count: number }>();

export function emailSettings(): EmailSettings {
  return { apiKey: process.env.RESEND_API_KEY ?? "", sender: process.env.REPORT_FROM_EMAIL ?? "", signingSecret: process.env.SESSION_REPORT_SECRET ?? "" };
}

export function emailAvailable(settings: EmailSettings): boolean {
  const address = settings.sender.match(/<([^<>]+)>$/)?.[1] ?? settings.sender;
  return settings.apiKey.startsWith("re_") && EMAIL.test(address) && !/[\r\n]/.test(settings.sender) && settings.signingSecret.length >= 32;
}

function response(body: object, status = 200) {
  return Response.json(body, { status, headers: HEADERS });
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
  return value as Record<string, unknown>;
}

function string(value: unknown, max = 2000): string {
  if (typeof value !== "string" || value.length > max || /\u0000/.test(value)) throw new Error("invalid");
  return value;
}

function strings(value: unknown, maxItems: number, maxLength: number): string[] {
  if (!Array.isArray(value) || value.length > maxItems) throw new Error("invalid");
  return value.map((item) => string(item, maxLength));
}

function integer(value: unknown, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) throw new Error("invalid");
  return value;
}

function percentage(value: unknown): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 100) throw new Error("invalid");
  return value;
}

function safeAssessment(value: unknown): NonNullable<ScanReport["scan"]["assessment"]> {
  const assessment = object(value);
  const planned = integer(assessment.planned_scopes, MAX_SCOPES);
  const completed = integer(assessment.completed_scopes, planned);
  if (!Array.isArray(assessment.pillars) || assessment.pillars.length > PILLARS.length) throw new Error("invalid");
  const seen = new Set<Pillar>();
  const pillars = assessment.pillars.map((raw) => {
    const item = object(raw);
    const pillar = string(item.pillar, 40) as Pillar;
    if (!PILLARS.includes(pillar) || seen.has(pillar)) throw new Error("invalid");
    seen.add(pillar);
    const ownPlanned = integer(item.planned_scopes, MAX_SCOPES);
    return { pillar, score: percentage(item.score), coverage: percentage(item.coverage),
      planned_scopes: ownPlanned, completed_scopes: integer(item.completed_scopes, ownPlanned) };
  });
  if (pillars.reduce((total, item) => total + item.planned_scopes, 0) !== planned ||
      pillars.reduce((total, item) => total + item.completed_scopes, 0) !== completed) throw new Error("invalid");
  return { version: string(assessment.version, 64), registry_version: string(assessment.registry_version, 64),
    overall_score: percentage(assessment.overall_score), evaluated_pillars: integer(assessment.evaluated_pillars, pillars.length),
    planned_scopes: planned, completed_scopes: completed, critical_failures: integer(assessment.critical_failures, 5000), pillars };
}

function safeScopes(value: unknown, regions: string[]): EmailScope[] {
  if (!Array.isArray(value) || value.length > MAX_SCOPES) throw new Error("invalid");
  const seen = new Set<string>();
  return value.map((raw) => {
    const scope = object(raw);
    const check = string(scope.check_id, 128);
    const pillar = string(scope.pillar, 40) as Pillar;
    const region = string(scope.region, 32);
    const status = string(scope.status, 20) as EmailScope["status"];
    const key = `${check}:${region}`;
    if (!/^[a-z0-9_]+$/.test(check) || !PILLARS.includes(pillar) ||
        (region !== "global" && !regions.includes(region)) ||
        !["queued", "running", "complete", "incomplete"].includes(status) || seen.has(key)) throw new Error("invalid");
    seen.add(key);
    return { check_id: check, pillar, region, status,
      ...(scope.reason_codes !== undefined ? { reason_codes: strings(scope.reason_codes, 20, 128) } : {}) };
  });
}

/** Project known report fields; unknown properties can never enter an attachment. */
export function safeEmailReport(value: unknown): EmailReport {
  const report = object(value);
  const scan = object(report.scan);
  const account = string(scan.account_id, 12);
  if (!/^\d{12}$/.test(account) || !Array.isArray(report.findings) || report.findings.length > 5000) throw new Error("invalid");
  const started = string(scan.started_at, 40);
  const finished = string(scan.finished_at, 40);
  if (!Number.isFinite(Date.parse(started)) || !Number.isFinite(Date.parse(finished)) || Date.parse(finished) < Date.parse(started)) throw new Error("invalid");
  const regions = strings(scan.regions, 6, 32);
  const checks = strings(scan.checks_run, 100, 128);
  if (regions.some((region) => !/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(region)) || checks.some((check) => !/^[a-z0-9_]+$/.test(check))) throw new Error("invalid");
  const findings: Finding[] = report.findings.map((raw) => {
    const item = object(raw);
    const pillar = string(item.pillar, 40) as Finding["pillar"];
    const severity = string(item.severity, 20) as Finding["severity"];
    const status = string(item.status, 30) as Finding["status"];
    if (!PILLARS.includes(pillar) || !SEVERITIES.includes(severity) || !STATUSES.includes(status) || item.account_id !== account) throw new Error("invalid");
    return {
      check_id: string(item.check_id, 128), title: string(item.title, 500), pillar, severity, status,
      resource_arn: string(item.resource_arn), resource_type: string(item.resource_type, 128),
      region: string(item.region, 32), account_id: account, description: string(item.description, 8000),
      remediation: string(item.remediation, 8000), scanned_at: string(item.scanned_at, 40),
      ...(typeof item.reason_code === "string" ? { reason_code: string(item.reason_code, 128) } : {}),
      ...(typeof item.resource_id === "string" ? { resource_id: string(item.resource_id) } : {}),
    };
  });
  const assessment = scan.assessment === undefined ? undefined : safeAssessment(scan.assessment);
  const scopes = report.scopes === undefined ? undefined : safeScopes(report.scopes, regions);
  if (assessment && scopes && (assessment.planned_scopes !== scopes.length ||
      assessment.completed_scopes !== scopes.filter((scope) => scope.status === "complete").length)) throw new Error("invalid");
  let execution: EmailReport["execution"];
  if (report.execution !== undefined) {
    const item = object(report.execution);
    if (!scopes || item.source !== "temporary_session" || typeof item.stopped !== "boolean") throw new Error("invalid");
    const settled = integer(item.settled_scopes, scopes.length);
    if (settled !== scopes.filter((scope) => scope.status === "complete" || scope.status === "incomplete").length) throw new Error("invalid");
    execution = { source: "temporary_session", stopped: item.stopped, settled_scopes: settled };
  }
  return { scan: { account_id: account, started_at: started, finished_at: finished, regions, checks_run: checks,
      ...(assessment ? { assessment } : {}) }, findings,
    ...(scopes ? { scopes } : {}), ...(execution ? { execution } : {}) };
}

type EmailProof = { account_id: string; email: string; expires_at: number; nonce: string };

export function verifyEmailToken(token: string, secret: string, now = Date.now()): EmailProof {
  if (secret.length < 32 || token.length > 2048) throw new Error("invalid");
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra !== undefined || !/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]+$/.test(signature)) throw new Error("invalid");
  const expected = createHmac("sha256", secret).update(payload).digest();
  const actual = Buffer.from(signature, "base64url");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("invalid");
  const proof = object(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")));
  if (typeof proof.account_id !== "string" || !/^\d{12}$/.test(proof.account_id) || typeof proof.email !== "string" || !EMAIL.test(proof.email) || proof.email.length > 254 || typeof proof.nonce !== "string" || !/^[a-f0-9]{32}$/.test(proof.nonce) || typeof proof.expires_at !== "number" || proof.expires_at * 1000 <= now || proof.expires_at * 1000 > now + 3_660_000) throw new Error("invalid");
  return proof as EmailProof;
}

async function limitedJson(request: Request): Promise<unknown> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > MAX_BYTES) throw new Error("too_large");
  if (!request.body) throw new Error("invalid");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) { await reader.cancel(); throw new Error("too_large"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

export function emailPayload(report: EmailReport, email: string, sender: string) {
  const failed = report.findings.filter((finding) => finding.status === "fail");
  const passed = report.findings.filter((finding) => finding.status === "pass").length;
  const unavailable = report.findings.filter((finding) => ["error", "unknown", "skipped"].includes(finding.status)).length;
  const account = report.scan.account_id;
  const planned = report.scopes?.length ?? report.scan.assessment?.planned_scopes;
  const completed = report.scopes?.filter((scope) => scope.status === "complete").length ?? report.scan.assessment?.completed_scopes;
  const incomplete = planned === undefined || completed === undefined ? undefined : planned - completed;
  const coverage = planned === undefined ? "Scope completion details were not supplied." : `${completed} of ${planned} planned scopes completed successfully.`;
  const warning = incomplete === undefined
    ? "Coverage could not be confirmed. This report does not establish that every requested check completed."
    : incomplete > 0
      ? `Warning: ${incomplete} of ${planned} scan scopes did not complete. Findings from those scopes may be missing; this report does not confirm a clean AWS posture.`
      : report.execution?.stopped ? "Warning: this scan was stopped. Review the scope details before relying on this report." : "";
  const summary = `AWS account ${account}: ${failed.length} failed, ${passed} passed, ${unavailable} unavailable evaluations. ${report.scan.checks_run.length} checks requested across ${report.scan.regions.join(", ")}.`;
  const top = failed.slice(0, 12).map((finding) => `<li><strong>${escapeHtml(finding.severity.toUpperCase())}</strong> ${escapeHtml(finding.title)}<br><small>${escapeHtml(finding.resource_arn)}</small></li>`).join("");
  return {
    from: sender, to: [email], subject: `LytaScan ${incomplete !== undefined && incomplete > 0 ? "incomplete report" : "report"} · AWS ${account}`,
    text: `${summary}\n\n${coverage}${warning ? `\n${warning}` : ""}\n\nCompleted: ${report.scan.finished_at}\n\nThe attached JSON contains all returned findings, unavailable checks, and remediation guidance. This report is a snapshot of the selected regions; review unavailable checks before relying on coverage. AWS credentials are not included.`,
    html: `<div style="font:15px/1.6 Arial,sans-serif;color:#102033;max-width:680px;margin:auto"><h1 style="font-size:25px;color:#175cd3">Your LytaScan report</h1><p>${escapeHtml(summary)}</p><p>${escapeHtml(coverage)}</p>${warning ? `<p style="border-left:3px solid #b54708;padding:10px 14px;color:#93370d"><strong>${escapeHtml(warning)}</strong></p>` : ""}<p>Completed: ${escapeHtml(report.scan.finished_at)}</p>${top ? `<h2 style="font-size:18px">Findings to review</h2><ul>${top}</ul>` : ""}<p>The attached JSON includes all returned findings and remediation guidance. Review unavailable checks before relying on coverage.</p><p style="color:#5b6b80">This report contains AWS resource information. Share it only with intended recipients. AWS credentials are not included.</p></div>`,
    attachments: [{ filename: `lytascan-${account}.json`, content: Buffer.from(JSON.stringify(report, null, 2)).toString("base64") }],
  };
}

/** Requires an AWS-verified, expiring capability bound to this recipient/account. */
export async function deliverReport(request: Request, settings: EmailSettings, fetcher: typeof fetch = fetch): Promise<Response> {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin || request.headers.get("sec-fetch-site") === "cross-site") return response({ error: "Send the report from the LytaScan scan page." }, 403);
  if (!request.headers.get("content-type")?.startsWith("application/json")) return response({ error: "Use a JSON report request." }, 415);
  if (!emailAvailable(settings)) return response({ error: "Automatic email delivery is unavailable. Download your report or open an email draft." }, 503);
  let email: string;
  let report: EmailReport;
  let proof: EmailProof;
  try {
    const body = object(await limitedJson(request));
    email = string(body.email, 254).trim().toLowerCase();
    if (!EMAIL.test(email)) throw new Error("invalid");
    report = safeEmailReport(body.report);
    proof = verifyEmailToken(string(body.email_token, 2048), settings.signingSecret);
    if (proof.email !== email || proof.account_id !== report.scan.account_id) throw new Error("invalid");
  } catch (error) {
    return response({ error: error instanceof Error && error.message === "too_large" ? "The email report is too large. Download it instead." : "This email request is invalid or expired. Reconnect to create a new report email." }, error instanceof Error && error.message === "too_large" ? 413 : 400);
  }
  const now = Date.now();
  for (const [key, bucket] of deliveries) if (bucket.until <= now) deliveries.delete(key);
  const budget = deliveries.get(proof.account_id) ?? { until: now + 3_600_000, count: 0 };
  if (budget.count >= 5 || deliveries.size >= 2048) return response({ error: "Email delivery limit reached. Download the report and try again later." }, 429);
  budget.count += 1;
  deliveries.set(proof.account_id, budget);
  try {
    const result = await fetcher("https://api.resend.com/emails", {
      method: "POST", headers: { Authorization: `Bearer ${settings.apiKey}`, "Content-Type": "application/json", "Idempotency-Key": `lytascan-report/${proof.nonce}` },
      body: JSON.stringify(emailPayload(report, email, settings.sender)), signal: AbortSignal.timeout(15_000),
    });
    if (!result.ok) return response({ error: "Email delivery could not complete. Your report is still available to download." }, 502);
    const receipt = object(await result.json());
    if (typeof receipt.id !== "string" || !receipt.id) throw new Error("provider");
    return response({ sent: true });
  } catch {
    return response({ error: "Email delivery could not complete. Your report is still available to download." }, 502);
  }
}
