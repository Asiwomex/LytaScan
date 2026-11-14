"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Activity, ChevronRight, Clock3, Play, Search } from "lucide-react";

import { Dashboard } from "@/components/dashboard";
import { TeamMembers } from "./team-members";
import { FindingLifecycle } from "./finding-lifecycle";
import { ScanProgress, ScanStatus, ScopeBar, scanLabel, type ScopeTotals } from "./scan-progress";
import { ACTION, FIELD, TEXT_LINK } from "./onboarding-auth";
import { LOCAL_ONBOARDING } from "@/lib/backend";
import { PILLARS, PILLAR_LABELS, type Pillar, type ScanReport } from "@/lib/findings";
import { onboardingRequest, type Connection } from "@/lib/onboarding";

type Job = {
  job_id: string;
  aws_account_id: string;
  state: string;
  region: string;
  counts: (Record<"pass" | "fail" | "error", number> & { unavailable?: number }) | null;
  error_message: string | null;
  source?: "legacy";
  kind?: "verification" | "full" | "scope_retry" | "quick" | "pillar";
  pillar?: Pillar | null;
  scope_progress?: ScopeTotals | null;
  created_at?: number;
  last_successful_at?: number | null;
  findings_reconciled?: boolean;
  reconciliation_expired?: boolean;
};
const reconciling = (job: Job) => job.findings_reconciled === false && !job.reconciliation_expired;
const jobActive = (job: Job) => ACTIVE.includes(job.state) || reconciling(job);
type Invite = { invite_id: string; email: string; status: string; role: string };
type Legacy = { scan_id: string; started_at: string; imported_job: string | null };
const ACTIVE = ["queued", "running"];
const RETRYABLE = ["partial", "failed", "expired"];
const PRIMARY = `${ACTION} gap-2 bg-[var(--console-accent)] hover:brightness-95`;

function formatDate(at?: number) {
  if (!at) return "—";
  return new Date(at * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function jobType(job: Job) {
  if (job.source === "legacy") return "Legacy import";
  if (job.kind === "verification") return "Finding verification";
  if (job.kind === "scope_retry") return "Scope retry";
  if (job.kind === "quick") return "Quick scan";
  if (job.kind === "pillar") return job.pillar ? PILLAR_LABELS[job.pillar] : "Pillar scan";
  return "Full scan";
}

export function OrganizationOperations({ orgId, role, token, onTransfer, connectionPanel }: {
  orgId: string; role: string; token: string; onTransfer: () => void; connectionPanel?: ReactNode;
}) {
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [inviteLink, setInviteLink] = useState("");
  const [legacy, setLegacy] = useState<{ account: string; items: Legacy[] }>();
  const [report, setReport] = useState<{ job: Job; data: ScanReport }>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanAccount, setScanAccount] = useState("");
  const [mode, setMode] = useState<"full" | "quick" | "pillar">("full");
  const [pillar, setPillar] = useState<Pillar>("security");
  const [progressId, setProgressId] = useState<string>();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const requests = useRef<Record<string, string>>({});
  const progressRef = useRef<HTMLDivElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const pendingRefresh = useRef(false);
  const manager = ["owner", "administrator"].includes(role);
  const canScan = manager || role === "engineer";
  const path = `/v1/orgs/${orgId}`;
  const request = useCallback(<T,>(suffix: string, body?: unknown) =>
    onboardingRequest<T>(`${path}${suffix}`, body, token), [path, token]);

  const refresh = useCallback(async () => {
    if (pendingRefresh.current) return;
    pendingRefresh.current = true;
    try {
      const [nextJobs, accounts, team] = await Promise.all([
        request<Job[]>("/jobs"),
        request<Connection[]>("/connections"),
        manager ? request<Invite[]>("/invites") : Promise.resolve([]),
      ]);
      setJobs(nextJobs);
      setConnections(accounts);
      setInvites(team);
    } finally {
      pendingRefresh.current = false;
    }
  }, [manager, request]);

  useEffect(() => {
    const initial = window.setTimeout(() => {
      void refresh().catch((problem: Error) => setError(problem.message));
    }, 0);
    return () => window.clearTimeout(initial);
  }, [refresh]);

  const active = jobs?.some(jobActive) ?? false;
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => {
      void refresh().catch((problem: Error) => setError(problem.message));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [active, refresh]);

  async function act(operation: () => Promise<void>) {
    setError("");
    setBusy(true);
    try {
      await operation();
      await refresh();
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Try again.");
    } finally {
      setBusy(false);
    }
  }

  function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setInviteLink("");
    void act(async () => {
      const issued = await request<{ token: string }>("/invites", {
        email: data.get("email"), role: data.get("role"), allowed_account: data.get("allowed_account") || null,
      });
      setInviteLink(`${window.location.origin}/organizations#invite=${issued.token}`);
      form.reset();
    });
  }

  async function run(account: string) {
    const key = `${account}:${mode}:${mode === "pillar" ? pillar : ""}`;
    const requestId = requests.current[key] ??= crypto.randomUUID();
    const job = await request<Job>(`/connections/${account}/jobs`, {
      request_id: requestId, mode, ...(mode === "pillar" ? { pillar } : {}),
    });
    delete requests.current[key];
    setJobs((current) => [job, ...(current ?? []).filter((item) => item.job_id !== job.job_id)]);
    openProgress(job.job_id);
  }

  function openProgress(id: string) {
    setProgressId(id);
    requestAnimationFrame(() => progressRef.current?.scrollIntoView({ block: "nearest" }));
  }

  function scopeRetry(jobId: string, scope: { check_id: string; region: string }) {
    const key = `${jobId}:${scope.check_id}:${scope.region}`;
    void act(async () => {
      const job = await request<Job>(`/jobs/${jobId}/retry-scope`, {
        request_id: requests.current[key] ??= crypto.randomUUID(), ...scope,
      });
      delete requests.current[key];
      setJobs((current) => [job, ...(current ?? []).filter((item) => item.job_id !== job.job_id)]);
      openProgress(job.job_id);
    });
  }

  async function preview(account: string) {
    const items = await request<Legacy[]>(`/connections/${account}/migration`);
    setLegacy({ account, items });
  }

  const accountNames = new Map(connections.map((item) => [item.aws_account_id, item.name]));
  const verified = connections.filter((item) => item.status === "verified");
  const selectedAccount = verified.some((item) => item.aws_account_id === scanAccount) ? scanAccount : verified[0]?.aws_account_id;
  const selectedJob = jobs?.find((job) => job.job_id === progressId);
  const lastSuccess = jobs?.find((job) => job.aws_account_id === selectedAccount && job.last_successful_at)?.last_successful_at;
  const query = search.trim().toLowerCase();
  const shown = jobs?.filter((job) =>
    (statusFilter === "all" || job.state === statusFilter || (statusFilter === "active" && jobActive(job))) &&
    (!query || [job.aws_account_id, accountNames.get(job.aws_account_id), job.region, jobType(job), scanLabel(job.state)]
      .some((part) => part?.toLowerCase().includes(query)))
  );

  return (
    <>
      {error && <p role="alert" className="rounded-md border border-line bg-surface p-3 text-critical">{error}</p>}
      <section id="scan-jobs" aria-labelledby="scan-jobs-heading" className="panel grid min-w-0 gap-4 p-4 sm:p-5">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-lg bg-[var(--console-accent-soft)] text-[var(--console-accent)]"><Activity size={18} aria-hidden="true" /></span>
          <div>
            <h2 id="scan-jobs-heading" className="text-lg font-semibold">Scan jobs</h2>
            {LOCAL_ONBOARDING && <p className="text-xs text-muted-ink">Fictional AWS data</p>}
          </div>
        </div>
        {canScan && selectedAccount && (
          <div className="flex flex-wrap items-end gap-3 rounded-lg border border-line bg-page p-3">
            <label className="min-w-0 text-xs font-medium">AWS account
              <select className={FIELD} value={selectedAccount} onChange={(event) => setScanAccount(event.target.value)}>
                {verified.map((item) => <option key={item.account_connection_id} value={item.aws_account_id}>{item.name} · {item.region}</option>)}
              </select>
            </label>
            <label className="text-xs font-medium">Scan type
              <select className={FIELD} value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}>
                <option value="full">Full scan</option><option value="quick">Quick scan</option><option value="pillar">Pillar scan</option>
              </select>
            </label>
            {mode === "pillar" && <label className="text-xs font-medium">Pillar
              <select className={FIELD} value={pillar} onChange={(event) => setPillar(event.target.value as Pillar)}>
                {PILLARS.map((value) => <option key={value} value={value}>{PILLAR_LABELS[value]}</option>)}
              </select>
            </label>}
            <button type="button" className={PRIMARY} disabled={busy || !!jobs?.some((job) =>
              job.aws_account_id === selectedAccount && jobActive(job))}
              onClick={() => void act(() => run(selectedAccount))}><Play size={15} aria-hidden="true" />Run scan</button>
            {role === "owner" && <button type="button" className={`${TEXT_LINK} mb-2`} disabled={busy}
              onClick={() => void act(() => preview(selectedAccount))}>Preview legacy history</button>}
          </div>
        )}
        {canScan && jobs && !connections.some((item) => item.status === "verified") && <p className="text-muted-ink">Verify an AWS connection to start a scan.</p>}
        {lastSuccess && <p className="text-xs text-muted-ink">Last complete full scan: {formatDate(lastSuccess)}</p>}
        {role === "owner" && LOCAL_ONBOARDING && connections.some((item) => item.aws_account_id === "111122223333" && item.status === "verified") &&
          <button type="button" className={`${TEXT_LINK} justify-self-start`} disabled={busy} onClick={() => void act(async () => {
            await onboardingRequest("/local/seed-legacy", {}, token);
            await preview("111122223333");
          })}>Load sample legacy history</button>}
        {legacy && <div className="rounded-lg bg-page p-3">
          <h3 className="font-semibold">Legacy history for {legacy.account}</h3>
          {legacy.items.length === 0 && <p className="mt-2 text-muted-ink">No eligible private legacy scans were found.</p>}
          <ul>{legacy.items.map((item) => <li key={item.scan_id} className="flex flex-wrap items-center gap-3 py-2">
            <time dateTime={item.started_at}>{item.started_at}</time>
            {item.imported_job ? <span>Imported</span> :
              <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => void act(async () => {
                await request(`/connections/${legacy.account}/migration`, { scan_id: item.scan_id });
                await preview(legacy.account);
              })}>Import scan</button>}
          </li>)}</ul>
        </div>}
        {jobs === null ? <p role="status">Loading scans…</p> : jobs.length === 0 ? <p className="text-muted-ink">No scans yet.</p> : <>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 rounded-md border border-line px-2.5">
              <Search size={15} aria-hidden="true" className="text-muted-ink" /><span className="sr-only">Search scan jobs</span>
              <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search scans" className="min-h-9 min-w-0 bg-transparent text-sm" />
            </label>
            <label><span className="sr-only">Filter scan status</span>
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className={`${FIELD} mt-0 min-h-9 text-sm`}>
                <option value="all">All statuses</option><option value="active">Active</option><option value="complete">Complete</option>
                <option value="partial">Partial</option><option value="failed">Failed</option><option value="expired">Expired</option><option value="cancelled">Cancelled</option>
              </select>
            </label>
          </div>
          {shown?.length === 0 ? <p className="text-muted-ink">No scans match these filters.</p> :
          <ul className="divide-y divide-line overflow-hidden rounded-lg border border-line">
            <li aria-hidden="true" className="hidden grid-cols-[minmax(0,1.2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,1fr)] gap-3 bg-page px-3 py-2 text-xs font-semibold text-muted-ink lg:grid">
              <span>Scan</span><span>Status</span><span>Rule scopes</span><span>Actions</span>
            </li>
            {shown?.map((job) => <li key={job.job_id} className="grid gap-3 p-3 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.7fr)_minmax(0,0.8fr)_minmax(0,1fr)] lg:items-center">
              <div className="min-w-0">
                <p className="font-medium">{jobType(job)}</p>
                <p className="text-xs text-muted-ink">{accountNames.get(job.aws_account_id) ?? job.aws_account_id} · {job.region}</p>
                <p className="mt-1 flex items-center gap-1 text-xs text-muted-ink"><Clock3 aria-hidden="true" size={12} />{formatDate(job.created_at)}</p>
                {reconciling(job) && <p className="text-sm text-muted-ink">Updating tracked findings…</p>}
                {job.error_message && <p className="text-sm text-muted-ink">{job.error_message}</p>}
              </div>
              <div><ScanStatus state={job.state} /></div>
              <div>{job.scope_progress ? <ScopeBar progress={job.scope_progress} /> : <span className="text-xs text-muted-ink">—</span>}</div>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                {job.scope_progress && <button type="button" className={`${TEXT_LINK} inline-flex items-center gap-0.5`}
                  onClick={() => openProgress(job.job_id)}>Progress<ChevronRight size={14} aria-hidden="true" /></button>}
                {["complete", "partial"].includes(job.state) && <button type="button" className={TEXT_LINK} disabled={busy}
                  onClick={() => void act(async () => {
                    setReport({ job, data: await request<ScanReport>(`/jobs/${job.job_id}/result`) });
                    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ block: "start" }));
                  })}>View results</button>}
                {ACTIVE.includes(job.state) && canScan && <button type="button" className={TEXT_LINK} disabled={busy}
                  onClick={() => void act(async () => { await request(`/jobs/${job.job_id}/cancel`, {}); })}>Cancel scan</button>}
                {job.source === "legacy" && role === "owner" && job.state !== "rolled_back" && <button type="button" className={TEXT_LINK} disabled={busy}
                  onClick={() => void act(async () => {
                    await request(`/jobs/${job.job_id}/rollback-import`, {});
                    if (report?.job.job_id === job.job_id) setReport(undefined);
                    if (legacy) await preview(legacy.account);
                  })}>Roll back import</button>}
              </div>
            </li>)}
          </ul>}</>}
      </section>
      {selectedJob && <div ref={progressRef}><ScanProgress key={selectedJob.job_id} orgId={orgId} token={token}
        jobId={selectedJob.job_id} state={selectedJob.state} live={jobActive(selectedJob)}
        accountName={accountNames.get(selectedJob.aws_account_id) ?? selectedJob.aws_account_id}
        busy={busy} onClose={() => setProgressId(undefined)}
        onRetry={canScan && RETRYABLE.includes(selectedJob.state) ? (scope) => scopeRetry(selectedJob.job_id, scope) : undefined} /></div>}
      {report && <div ref={resultsRef} className="min-w-0 scroll-mt-20"><Dashboard key={report.job.job_id} caption="Organization scan" scans={[{
        id: report.job.job_id, label: report.job.aws_account_id, note: report.job.source === "legacy"
          ? "Imported legacy report." : "Organization scan report.", report: report.data,
      }]} /></div>}
      {jobs !== null && <FindingLifecycle orgId={orgId} token={token} role={role} connections={connections}
        scanVersion={jobs.map((job) => `${job.job_id}:${job.state}:${job.findings_reconciled}`).join(",")} onJob={refresh} />}
      {connectionPanel}
      {manager && <div id="workspace-team" className="grid gap-4">
        {jobs !== null && <TeamMembers orgId={orgId} role={role} token={token} connections={connections} onTransfer={onTransfer} />}
        <section className="panel grid gap-4 p-4 sm:p-5">
          <h2 className="text-lg font-semibold">Team invitations</h2>
          <form onSubmit={invite} className="grid gap-3 sm:grid-cols-2">
            <label>Email<input className={FIELD} type="email" name="email" required maxLength={254} /></label>
            <label>Role<select className={FIELD} name="role">
              <option value="viewer">Viewer</option><option value="engineer">Engineer</option>
              <option value="security_analyst">Security analyst</option><option value="finance_analyst">Finance analyst</option>
              {role === "owner" && <option value="administrator">Administrator</option>}
            </select></label>
            <label>AWS connection<select className={FIELD} name="allowed_account">
              <option value="">Select a connection for scoped roles</option>
              {connections.map((item) => <option key={item.account_connection_id} value={item.account_connection_id}>{item.name}</option>)}
            </select></label>
            <button className={`${PRIMARY} self-end justify-self-start`} disabled={busy}>Create invitation</button>
          </form>
          {inviteLink && <label>Share this one-time link
            <input className={FIELD} readOnly value={inviteLink} onFocus={(event) => event.target.select()} />
          </label>}
          {invites.length > 0 && <ul className="divide-y divide-line">
            {invites.map((item) => <li key={item.invite_id} className="flex flex-wrap items-center gap-3 py-2">
              <span className="break-all">{item.email} · {item.role.replaceAll("_", " ")} · {item.status}</span>
              {item.status === "pending" && <button type="button" className={TEXT_LINK} disabled={busy}
                onClick={() => void act(async () => { await request("/invites/revoke", { invite_id: item.invite_id }); setInviteLink(""); })}>
                Revoke invitation
              </button>}
            </li>)}
          </ul>}
        </section>
      </div>}
    </>
  );
}
