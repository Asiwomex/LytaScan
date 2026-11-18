import { PILLARS, type Finding, type Pillar, type ScanReport, type Status } from "../../lib/findings";

export type TemporaryCredentials = { access_key_id: string; secret_access_key: string; session_token: string };
export type Scope = { check_id: string; pillar: Pillar; region: string };
export type ScopeState = Scope & { status: "queued" | "running" | "complete" | "incomplete"; reason_codes?: string[] };
export type CatalogCheck = { check_id: string; title: string; primary_pillar: Pillar; scope: string };
export type Inspection = { account_id: string; principal_arn: string; registry_version: string; regions: string[]; checks: CatalogCheck[]; scopes: Scope[]; email_token?: string | null };
export type Evaluation = { account_id: string; check_id: string; region: string; scope: ScopeState; findings: Finding[]; started_at: string; finished_at: string };
export type SessionReport = ScanReport & { scopes: ScopeState[]; execution: { source: "temporary_session"; stopped: boolean; settled_scopes: number } };
export type QueueControl = { stopped: boolean };

export function scopeKey(scope: Scope): string { return `${scope.check_id}:${scope.region}`; }

/** Stopping drains dispatched work; it never mistakes an aborted fetch for revoked AWS access. */
export async function runScopeQueue<T>(
  scopes: readonly Scope[],
  evaluate: (scope: Scope) => Promise<T>,
  control: QueueControl,
  callbacks: { started: (scope: Scope) => void; settled: (scope: Scope, result: T | null) => void },
): Promise<void> {
  let cursor = 0;
  async function worker() {
    while (!control.stopped) {
      const scope = scopes[cursor++];
      if (!scope) return;
      callbacks.started(scope);
      let result: T | null = null;
      try { result = await evaluate(scope); } catch { /* Never expose an AWS exception or credentials. */ }
      callbacks.settled(scope, result);
    }
  }
  await Promise.all([worker(), worker()]);
}

export function makeReport(identity: Inspection, findings: Finding[], scopes: ScopeState[], startedAt: string, stopped: boolean): SessionReport {
  const weights = { critical: 10, high: 5, medium: 3, low: 1 };
  const rawScores: number[] = [];
  const pillars = PILLARS.map((pillar) => {
    const own = findings.filter((finding) => finding.pillar === pillar);
    const evaluated = own.filter((finding) => finding.status === "pass" || finding.status === "fail");
    const unavailable = own.filter((finding) => ["error", "unknown", "skipped"].includes(finding.status)).length;
    const total = evaluated.reduce((sum, finding) => sum + weights[finding.severity], 0);
    const passed = evaluated.filter((finding) => finding.status === "pass").reduce((sum, finding) => sum + weights[finding.severity], 0);
    const ownScopes = scopes.filter((scope) => scope.pillar === pillar);
    if (total) rawScores.push((100 * passed) / total);
    return { pillar, score: total ? Math.round((10000 * passed) / total) / 100 : null,
      coverage: evaluated.length + unavailable ? Math.round((10000 * evaluated.length) / (evaluated.length + unavailable)) / 100 : null,
      planned_scopes: ownScopes.length, completed_scopes: ownScopes.filter((scope) => scope.status === "complete").length };
  });
  const scores = rawScores;
  return {
    scan: { account_id: identity.account_id, started_at: startedAt, finished_at: new Date().toISOString(), regions: identity.regions,
      checks_run: [...new Set(scopes.filter((scope) => scope.status !== "queued").map((scope) => scope.check_id))],
      assessment: { version: "2.0.0", registry_version: identity.registry_version, overall_score: scores.length ? Math.round((scores.reduce((sum, value) => sum + value, 0) / scores.length) * 100) / 100 : null,
        evaluated_pillars: scores.length, planned_scopes: scopes.length, completed_scopes: scopes.filter((scope) => scope.status === "complete").length,
        critical_failures: findings.filter((finding) => finding.status === "fail" && finding.severity === "critical").length, pillars } },
    findings: [...findings], scopes: scopes.map((scope) => ({ ...scope })),
    execution: { source: "temporary_session", stopped, settled_scopes: scopes.filter((scope) => scope.status === "complete" || scope.status === "incomplete").length },
  };
}

function csvCell(value: string): string {
  // Spreadsheet formula cells remain inert even if an AWS resource name starts with whitespace.
  const safe = /^[\u0000-\u0020]*[=+\-@]|^[\t\r\n]/.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}

export function reportCsv(report: SessionReport): string {
  const fields: (keyof Finding)[] = ["check_id", "title", "pillar", "severity", "status", "resource_arn", "resource_type", "region", "account_id", "description", "remediation", "scanned_at", "reason_code"];
  return "\ufeff" + [fields.join(","), ...report.findings.map((finding) => fields.map((field) => csvCell(finding[field] ?? "")).join(","))].join("\r\n");
}

export function resultCounts(findings: Finding[]): Record<Status, number> {
  const counts: Record<Status, number> = { pass: 0, fail: 0, error: 0, unknown: 0, skipped: 0, not_applicable: 0 };
  for (const finding of findings) counts[finding.status] += 1;
  return counts;
}

export function emailDraft(email: string, report: SessionReport): string {
  const counts = resultCounts(report.findings);
  const subject = `LytaScan report — AWS ${report.scan.account_id}`;
  const body = `LytaScan read-only AWS posture report\n\nAccount: ${report.scan.account_id}\nRegions: ${report.scan.regions.join(", ")}\nFinished: ${report.scan.finished_at}\nFailed findings: ${counts.fail}\nPassed evaluations: ${counts.pass}\nCompleted scopes: ${report.scan.assessment?.completed_scopes}/${report.scopes.length}\n\nAttach the downloaded JSON or CSV report before sending. Credentials are never included in the report.`;
  return `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
