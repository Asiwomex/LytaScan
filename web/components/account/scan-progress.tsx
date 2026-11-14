"use client";

import { useEffect, useState } from "react";
import { Check, CircleAlert, Clock3, LoaderCircle, X } from "lucide-react";

import { Pillar, PILLAR_LABELS } from "@/lib/findings";
import { onboardingRequest } from "@/lib/onboarding";
import { FIELD, TEXT_LINK } from "./onboarding-auth";

export type ScopeTotals = { total: number; settled: number; running: number; incomplete: number };
type ScanScope = {
  check_id: string;
  pillar: Pillar;
  region: string;
  status: string;
  counts?: { pass?: number; fail?: number; error?: number; unknown?: number; skipped?: number; not_applicable?: number };
  reason_codes?: string[];
  started_at?: number | null;
  finished_at?: number | null;
};
type ScopeReport = ScopeTotals & { scopes: ScanScope[] };

const SCAN_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  complete: "Complete",
  partial: "Partial",
  incomplete: "Incomplete",
  cancelled: "Cancelled",
  failed: "Failed",
  expired: "Expired",
  rolled_back: "Rolled back",
};

const ATTENTION = ["incomplete", "failed", "expired"];
export const scanLabel = (state: string) => SCAN_LABELS[state] ?? state.replaceAll("_", " ");

export function ScanStatus({ state }: { state: string }) {
  const Icon = state === "running" ? LoaderCircle : state === "complete" ? Check :
    [...ATTENTION, "partial"].includes(state) ? CircleAlert : Clock3;
  const tone = state === "complete" ? "bg-sound-tint text-sound" :
    state === "running" ? "bg-[var(--console-accent-soft)] text-[var(--console-accent)]" :
      [...ATTENTION, "partial"].includes(state) ? "bg-amber-50 text-amber-800" : "bg-page text-muted-ink";
  return (
    <span className={`inline-flex w-fit items-center gap-1 rounded-full px-2 py-0.5 text-[0.6875rem] font-semibold whitespace-nowrap ${tone}`}>
      <Icon aria-hidden="true" size={12} className={state === "running" ? "motion-safe:animate-spin" : undefined} /> {scanLabel(state)}
    </span>
  );
}

export function ScopeBar({ progress, label = "Rule scopes finished" }: { progress: ScopeTotals; label?: string }) {
  const percentage = progress.total ? Math.round(100 * progress.settled / progress.total) : 0;
  return (
    <div className="flex min-w-0 items-center gap-2">
      <progress value={progress.settled} max={progress.total || 1} aria-label={label}
        className="h-1.5 min-w-9 flex-1 appearance-none overflow-hidden rounded-full bg-page [&::-moz-progress-bar]:rounded-full [&::-moz-progress-bar]:bg-[var(--console-accent)] [&::-webkit-progress-bar]:bg-page [&::-webkit-progress-value]:rounded-full [&::-webkit-progress-value]:bg-[var(--console-accent)]" />
      <span className="text-xs font-medium text-muted-ink tabular-nums" aria-label={`${percentage}% finished`}>
        {progress.settled}/{progress.total}
      </span>
    </div>
  );
}

function scopeTime(value?: number | null) {
  if (!value) return "—";
  return new Date(value * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ScanProgress({ orgId, token, jobId, state, live, accountName, busy, onClose, onRetry }: {
  orgId: string;
  token: string;
  jobId: string;
  state: string;
  live: boolean;
  accountName: string;
  busy: boolean;
  onClose: () => void;
  onRetry?: (scope: Pick<ScanScope, "check_id" | "region">) => void;
}) {
  const [report, setReport] = useState<ScopeReport>();
  const [problem, setProblem] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [onlyAttention, setOnlyAttention] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let stopped = false;
    let pending = false;
    async function refresh() {
      if (pending) return;
      pending = true;
      try {
        const result = await onboardingRequest<ScopeReport>(`/v1/orgs/${orgId}/jobs/${jobId}/scopes`, undefined, token);
        if (!stopped) { setReport(result); setProblem(""); }
      } catch (error) {
        if (!stopped) setProblem(error instanceof Error ? error.message : "Scan progress is unavailable.");
      } finally {
        pending = false;
      }
    }
    const initial = window.setTimeout(() => void refresh(), 0);
    const timer = live ? window.setInterval(() => void refresh(), 1500) : undefined;
    return () => {
      stopped = true;
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [orgId, token, jobId, state, live, attempt]);

  const search = query.trim().toLowerCase();
  const scopes = report?.scopes.filter((scope) =>
    (!onlyAttention || ATTENTION.includes(scope.status)) &&
    (!search || [scope.check_id, scanLabel(scope.status), PILLAR_LABELS[scope.pillar], scope.region]
      .some((value) => value?.toLowerCase().replaceAll("_", " ").includes(search.replaceAll("_", " "))))
  ) ?? [];

  return (
    <section id="scan-progress" aria-labelledby="progress-heading" className="panel min-w-0 overflow-hidden">
      <div className="flex items-start justify-between gap-3 border-b border-line px-4 py-3.5 sm:px-5">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 id="progress-heading" className="text-base font-semibold">Scan progress</h2>
            <ScanStatus state={state} />
          </div>
          <p className="mt-1 text-sm text-muted-ink">{accountName}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close progress"
          className="grid size-9 shrink-0 place-items-center rounded-md border border-line bg-surface text-muted-ink hover:bg-page">
          <X aria-hidden="true" size={16} />
        </button>
      </div>
      {problem && (
        <p role="alert" className="border-b border-line px-4 py-3 text-critical sm:px-5">
          {problem} <button type="button" className={TEXT_LINK} onClick={() => setAttempt((value) => value + 1)}>Reload progress</button>
        </p>
      )}
      {!report && !problem && <p role="status" className="px-4 py-5 text-muted-ink sm:px-5">Loading scope progress…</p>}
      {report && report.total === 0 && <p className="px-4 py-5 text-muted-ink sm:px-5">No rule scopes were recorded for this scan.</p>}
      {report && report.total > 0 && (
        <>
          <div className="grid gap-3 border-b border-line px-4 py-3.5 sm:grid-cols-[minmax(0,1fr)_minmax(160px,0.45fr)] sm:items-center sm:px-5">
            <p className="text-xs text-muted-ink" aria-live="polite">
              <span className="font-semibold text-ink">{report.settled} of {report.total} scopes finished</span>
              {report.running > 0 && <span> · {report.running} running</span>}
              {report.incomplete > 0 && <span> · {report.incomplete} need review</span>}
            </p>
            <ScopeBar progress={report} />
          </div>
          <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2 sm:px-5">
            <label>
              <span className="sr-only">Filter scopes</span>
              <input className={`${FIELD} mt-0 min-h-9`} type="search" value={query} placeholder="Find a rule or region"
                onChange={(event) => setQuery(event.target.value)} />
            </label>
            <label className="inline-flex min-h-9 items-center gap-2 text-xs text-muted-ink">
              <input type="checkbox" checked={onlyAttention} onChange={(event) => setOnlyAttention(event.target.checked)} />
              Needs review
            </label>
          </div>
          {scopes.length === 0 ? <p className="px-4 py-5 text-muted-ink sm:px-5">No scopes match these filters.</p> : (
            <div className="max-h-[29rem] overflow-auto">
              <table className="w-full border-collapse text-left text-xs">
                <caption className="sr-only">Progress by scanner rule and region</caption>
                <thead className="sticky top-0 bg-page text-muted-ink">
                  <tr><th scope="col" className="px-4 py-2.5 font-medium sm:px-5">Rule</th>
                    <th scope="col" className="hidden px-3 py-2.5 font-medium sm:table-cell">Region</th>
                    <th scope="col" className="px-3 py-2.5 font-medium">Status</th>
                    <th scope="col" className="hidden px-3 py-2.5 font-medium lg:table-cell">Timing</th>
                    {onRetry && <th scope="col" className="px-3 py-2.5 font-medium"><span className="sr-only">Action</span></th>}</tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {scopes.map((scope) => (
                    <tr key={`${scope.check_id}:${scope.region}`}>
                      <td className="px-4 py-2.5 sm:px-5">
                        <span className="block break-all font-medium text-ink">{scope.check_id.replaceAll("_", " ")}</span>
                        <span className="text-[0.6875rem] text-muted-ink">{PILLAR_LABELS[scope.pillar] ?? scope.pillar}<span className="sm:hidden"> · {scope.region}</span></span>
                      </td>
                      <td className="hidden px-3 py-2.5 font-mono text-muted-ink sm:table-cell">{scope.region}</td>
                      <td className="px-3 py-2.5">
                        <ScanStatus state={scope.status} />
                        {scope.counts && <span className="mt-1 block whitespace-nowrap text-[0.6875rem] text-muted-ink">
                          {scope.counts.pass ?? 0} passed · {scope.counts.fail ?? 0} failed
                        </span>}
                        {!!scope.reason_codes?.length && <span className="mt-0.5 block text-[0.6875rem] text-muted-ink">{scope.reason_codes.map((reason) => reason.replaceAll("_", " ")).join(", ")}</span>}
                      </td>
                      <td className="hidden px-3 py-2.5 text-muted-ink lg:table-cell">
                        {scope.started_at && <span className="block">Start {scopeTime(scope.started_at)}</span>}
                        {scope.finished_at && <span className="block">Finish {scopeTime(scope.finished_at)}</span>}
                        {!scope.started_at && !scope.finished_at && "—"}
                      </td>
                      {onRetry && <td className="px-3 py-2.5">{ATTENTION.includes(scope.status) && (
                        <button type="button" aria-label={`Retry ${scope.check_id.replaceAll("_", " ")} in ${scope.region}`}
                          disabled={busy} className={TEXT_LINK} onClick={() => onRetry(scope)}>Retry</button>
                      )}</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
