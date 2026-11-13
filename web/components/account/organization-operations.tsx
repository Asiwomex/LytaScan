"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { Dashboard } from "@/components/dashboard";
import { ACTION, FIELD, TEXT_LINK } from "./onboarding-auth";
import { LOCAL_ONBOARDING } from "@/lib/backend";
import type { ScanReport } from "@/lib/findings";
import { onboardingRequest, type Connection } from "@/lib/onboarding";

type Job = {
  job_id: string;
  aws_account_id: string;
  state: string;
  region: string;
  counts: Record<"pass" | "fail" | "error", number> | null;
  error_message: string | null;
  source?: "legacy";
};
type Invite = { invite_id: string; email: string; status: string; role: string };
type Legacy = { scan_id: string; started_at: string; imported_job: string | null };
const ACTIVE = ["queued", "running"];

export function OrganizationOperations({ orgId, role, token }: { orgId: string; role: string; token: string }) {
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [inviteLink, setInviteLink] = useState("");
  const [legacy, setLegacy] = useState<{ account: string; items: Legacy[] }>();
  const [report, setReport] = useState<{ job: Job; data: ScanReport }>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const requests = useRef<Record<string, string>>({});
  const manager = ["owner", "administrator"].includes(role);
  const canScan = manager || role === "engineer";
  const path = `/v1/orgs/${orgId}`;
  const request = useCallback(<T,>(suffix: string, body?: unknown) =>
    onboardingRequest<T>(`${path}${suffix}`, body, token), [path, token]);

  const refresh = useCallback(async () => {
    const [nextJobs, accounts, team] = await Promise.all([
      request<Job[]>("/jobs"),
      request<Connection[]>("/connections"),
      manager ? request<Invite[]>("/invites") : Promise.resolve([]),
    ]);
    setJobs(nextJobs);
    setConnections(accounts);
    setInvites(team);
  }, [manager, request]);

  useEffect(() => {
    const initial = window.setTimeout(() => {
      void refresh().catch((problem: Error) => setError(problem.message));
    }, 0);
    return () => window.clearTimeout(initial);
  }, [refresh]);

  const active = jobs?.some((job) => ACTIVE.includes(job.state)) ?? false;
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
    const requestId = requests.current[account] ??= crypto.randomUUID();
    await request(`/connections/${account}/jobs`, { request_id: requestId });
    delete requests.current[account];
  }

  async function preview(account: string) {
    const items = await request<Legacy[]>(`/connections/${account}/migration`);
    setLegacy({ account, items });
  }

  return (
    <>
      {error && <p role="alert" className="rounded-md bg-night-raised p-3">{error}</p>}
      {manager && (
        <section className="panel grid gap-4 p-4 text-ink sm:p-5">
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
            <button className={`${ACTION} self-end justify-self-start`} disabled={busy}>Create invitation</button>
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
      )}
      <section className="panel grid gap-4 p-4 text-ink sm:p-5">
        <h2 className="text-lg font-semibold">Scan jobs</h2>
        {LOCAL_ONBOARDING && <p className="text-sm text-muted-ink">Local jobs run against fictional scan data.</p>}
        {canScan && connections.filter((item) => item.status === "verified").map((item) => (
          <div key={item.account_connection_id} className="flex flex-wrap items-center gap-3">
            <span className="font-medium">{item.name} · {item.region}</span>
            <button type="button" className={ACTION} disabled={busy || !!jobs?.some((job) =>
              job.aws_account_id === item.aws_account_id && ACTIVE.includes(job.state))}
              onClick={() => void act(() => run(item.aws_account_id))}>Run scan</button>
            {role === "owner" && <button type="button" className={TEXT_LINK} disabled={busy}
              onClick={() => void act(() => preview(item.aws_account_id))}>Preview legacy history</button>}
          </div>
        ))}
        {canScan && jobs && !connections.some((item) => item.status === "verified") && <p className="text-muted-ink">Verify an AWS connection to start a scan.</p>}
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
        {jobs === null ? <p role="status">Loading scans…</p> : jobs.length === 0 ? <p className="text-muted-ink">No scans yet.</p> :
          <ul className="divide-y divide-line rounded-lg border border-line">
            {jobs.map((job) => <li key={job.job_id} className="flex flex-wrap items-center justify-between gap-3 p-3">
              <div>
                <p className="font-medium">{job.aws_account_id} · {job.region} · {job.state.replaceAll("_", " ")}</p>
                {job.source === "legacy" && <p className="text-sm text-muted-ink">Imported from legacy history</p>}
                {job.counts && <p className="text-sm text-muted-ink">{job.counts.pass} passed · {job.counts.fail} failed · {job.counts.error} errors</p>}
                {job.error_message && <p className="text-sm text-muted-ink">{job.error_message}</p>}
              </div>
              <div className="flex flex-wrap gap-3">
                {["complete", "partial"].includes(job.state) && <button type="button" className={TEXT_LINK} disabled={busy}
                  onClick={() => void act(async () => setReport({ job, data: await request<ScanReport>(`/jobs/${job.job_id}/result`) }))}>View results</button>}
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
          </ul>}
      </section>
      {report && <Dashboard key={report.job.job_id} caption="Organization scan" scans={[{
        id: report.job.job_id, label: report.job.aws_account_id, note: report.job.source === "legacy"
          ? "Imported legacy report." : "Organization scan report.", report: report.data,
      }]} />}
    </>
  );
}
