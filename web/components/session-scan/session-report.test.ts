import { describe, expect, it } from "vitest";
import type { Finding } from "../../lib/findings";
import { emailDraft, makeReport, reportCsv, runScopeQueue, type Inspection, type Scope, type ScopeState } from "./session-report";

const identity: Inspection = { account_id: "111122223333", principal_arn: "arn:aws:sts::111122223333:assumed-role/Audit/test", regions: ["us-east-1"], registry_version: "2.1.0", checks: [], scopes: [] };
function finding(changes: Partial<Finding> = {}): Finding { return { check_id: "example", title: "Example check", pillar: "security", severity: "high", status: "fail", resource_arn: "arn:aws:ec2:us-east-1:111122223333:instance/i-test", resource_type: "AWS::EC2::Instance", region: "us-east-1", account_id: "111122223333", description: "Observed configuration", remediation: "Review the setting", scanned_at: "2026-11-18T11:00:00Z", ...changes }; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
const scopes: Scope[] = [0, 1, 2, 3].map((index) => ({ check_id: `check_${index}`, pillar: "security", region: "us-east-1" }));

describe("temporary scan request queue", () => {
  it("limits concurrent AWS scopes to two", async () => {
    let active = 0; let largest = 0;
    const finished: string[] = [];
    await runScopeQueue(scopes, async (scope) => { active += 1; largest = Math.max(largest, active); await Promise.resolve(); active -= 1; return scope.check_id; }, { stopped: false }, { started: () => {}, settled: (_scope, result) => { if (result) finished.push(result); } });
    expect(largest).toBe(2); expect(finished).toHaveLength(4);
  });
  it("stops new scopes and waits for dispatched requests to finish before disconnect can clear", async () => {
    const first = deferred<string>(); const second = deferred<string>(); const control = { stopped: false };
    const started: string[] = []; const settled: string[] = []; let drained = false;
    const running = runScopeQueue(scopes, (scope) => scope.check_id === "check_0" ? first.promise : second.promise, control, { started: (scope) => started.push(scope.check_id), settled: (scope) => settled.push(scope.check_id) }).then(() => { drained = true; });
    expect(started).toEqual(["check_0", "check_1"]);
    control.stopped = true; first.resolve("first"); await Promise.resolve(); await Promise.resolve();
    expect(drained).toBe(false); expect(started).toHaveLength(2);
    second.resolve("second"); await running;
    expect(drained).toBe(true); expect(settled).toHaveLength(2); expect(started).toHaveLength(2);
  });
  it("marks failed requests unavailable without leaking thrown exception content", async () => {
    const results: unknown[] = [];
    await runScopeQueue(scopes.slice(0, 1), async () => { throw new Error("AWS secret must never reach the UI"); }, { stopped: false }, { started: () => {}, settled: (_scope, result) => results.push(result) });
    expect(results).toEqual([null]);
  });
});

describe("portable session reports", () => {
  const states: ScopeState[] = [{ check_id: "example", pillar: "security", region: "us-east-1", status: "complete" }, { check_id: "denied", pillar: "cost", region: "us-east-1", status: "incomplete", reason_codes: ["access_denied"] }];
  it("preserves incomplete coverage and excludes identity/email tokens from downloads", () => {
    const report = makeReport({ ...identity, email_token: "private-email-ticket" }, [finding()], states, "2026-11-18T10:00:00Z", false);
    expect(report.scan.assessment?.planned_scopes).toBe(2); expect(report.scan.assessment?.completed_scopes).toBe(1);
    expect(report.scopes[1].reason_codes).toEqual(["access_denied"]);
    expect(report.scan.assessment?.pillars).toHaveLength(6);
    expect(JSON.stringify(report)).not.toContain("private-email-ticket"); expect(JSON.stringify(report)).not.toContain("principal_arn");
  });
  it("scores v2 high-severity findings at weight five", () => {
    const report = makeReport(identity, [finding({ status: "pass", severity: "high" }), finding({ status: "fail", severity: "low" })], states, "2026-11-18T10:00:00Z", false);
    expect(report.scan.assessment?.overall_score).toBe(83.33);
  });
  it("quotes CSV values and neutralizes spreadsheet formulas from resource names", () => {
    const report = makeReport(identity, [finding({ title: 'A "quoted" finding', resource_arn: '  =HYPERLINK("https://untrusted.example")' })], states, "2026-11-18T10:00:00Z", false);
    const csv = reportCsv(report);
    expect(csv).toContain('"A ""quoted"" finding"'); expect(csv).toContain('"\'  =HYPERLINK('); expect(csv.startsWith("\ufeff")).toBe(true);
  });
  it("creates an explicit draft without credentials or claiming an attachment was sent", () => {
    const report = makeReport(identity, [finding()], states, "2026-11-18T10:00:00Z", false);
    const draft = decodeURIComponent(emailDraft("recipient@example.test", report));
    expect(draft).toContain("mailto:recipient@example.test"); expect(draft).toContain("Attach the downloaded JSON or CSV report before sending."); expect(draft).not.toContain("secret_access_key");
  });
});
