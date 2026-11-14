"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { ACTION, FIELD, TEXT_LINK } from "./onboarding-auth";
import { onboardingRequest, type Connection } from "@/lib/onboarding";
import { LOCAL_ONBOARDING } from "@/lib/backend";
import { ChevronRight, CircleCheck, ClipboardList } from "lucide-react";

const STATES = ["open", "acknowledged", "in_progress", "resolved", "risk_accepted", "false_positive", "suppressed"];
const EXCEPTIONS = new Set(STATES.slice(4));
const title = (text: string) => text.replaceAll("_", " ");
type Lifecycle = {
  finding_id: string; title: string; check_id: string; workflow_status: string; outcome: string;
  outcome_reason: string | null; severity: string; evidence: string | null; remediation: string;
  resource_arn: string; first_seen: string; last_seen: string; last_observed_at: string;
  rule_version: string; registry_version: string; revision: string;
  exception_reason: string | null; exception_until: number | null;
  resolution_reason: string | null;
};
type History = { event_id: string; action: string; at: string; actor: string; note: string | null; workflow_status: string };
type Detail = Lifecycle & { history: History[] };
type Page = { findings: Lifecycle[]; next_cursor: string | null };

export function FindingLifecycle({ orgId, token, role, connections, scanVersion, onJob }: {
  orgId: string; token: string; role: string; connections: Connection[]; scanVersion: string; onJob: () => Promise<void>;
}) {
  const [account, setAccount] = useState(connections[0]?.aws_account_id ?? "");
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState<Page>();
  const [cursor, setCursor] = useState("");
  const [detail, setDetail] = useState<Detail>();
  const [nextState, setNextState] = useState("acknowledged");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);
  const verification = useRef<Record<string, string>>({});
  const selected = connections.some((item) => item.aws_account_id === account) ? account : connections[0]?.aws_account_id;
  const path = `/v1/orgs/${orgId}/connections/${selected}/findings`;
  const canEdit = ["owner", "administrator", "engineer", "security_analyst"].includes(role);
  const canScan = ["owner", "administrator", "engineer"].includes(role);

  const getDetail = useCallback((id: string) => onboardingRequest<Detail>(`${path}/${id}`, undefined, token), [path, token]);
  const opened = detail?.finding_id;
  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    const query = new URLSearchParams({ limit: "30" });
    if (filter) query.set("status", filter);
    if (cursor) query.set("cursor", cursor);
    onboardingRequest<Page>(`${path}?${query}`, undefined, token)
      .then((value) => { if (!cancelled) setPage(value); })
      .catch((problem: Error) => { if (!cancelled) { setPage(undefined); setError(problem.message); } });
    return () => { cancelled = true; };
  }, [path, token, selected, filter, cursor, revision, scanVersion]);

  useEffect(() => {
    if (!opened) return;
    let cancelled = false;
    getDetail(opened).then((value) => { if (!cancelled) setDetail(value); })
      .catch((problem: Error) => { if (!cancelled) { setDetail(undefined); setError(problem.message); } });
    return () => { cancelled = true; };
  }, [getDetail, opened, scanVersion]);

  async function act(operation: () => Promise<void>) {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      await operation();
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Try again.");
    } finally {
      setBusy(false);
    }
  }

  function update(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!detail) return;
    const fields = new FormData(event.currentTarget);
    const days = Number(fields.get("days"));
    const reason = String(fields.get("reason") ?? "").trim();
    void act(async () => {
      await onboardingRequest(`${path}/${detail.finding_id}`, {
        status: nextState, revision: detail.revision, reason: reason || null,
        expires_at: EXCEPTIONS.has(nextState) ? Math.floor(Date.now() / 1000) + days * 86400 - 5 : null,
      }, token, "PATCH");
      setDetail(await getDetail(detail.finding_id));
      setRevision((value) => value + 1);
      setNotice("Finding updated.");
    });
  }

  return (
    <section id="tracked-findings" aria-labelledby="lifecycle-heading" className="panel grid min-w-0 scroll-mt-24 gap-4 p-4 text-ink sm:p-5">
      <div className="flex items-center gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-line bg-page text-muted-ink">
          <ClipboardList size={17} aria-hidden="true" />
        </span>
        <h2 id="lifecycle-heading" className="text-lg font-semibold tracking-tight">Tracked findings</h2>
      </div>
      {error && <p role="alert" className="text-critical">{error}{" "}
        <button type="button" className={TEXT_LINK} onClick={() => {
          setError(""); setRevision((value) => value + 1);
          if (opened) void act(async () => setDetail(await getDetail(opened)));
        }}>Reload findings</button>
      </p>}
      {notice && <p role="status" className="text-sound">{notice}</p>}
      {!selected ? <p className="text-muted-ink">Connect an AWS account and run a scan to track findings.</p> : (
        <>
          <div className="flex flex-wrap gap-3">
            <label>Connection<select className={FIELD} value={selected} onChange={(event) => {
              setAccount(event.target.value); setCursor(""); setDetail(undefined); setPage(undefined);
            }}>
              {connections.map((item) => <option key={item.account_connection_id} value={item.aws_account_id}>{item.name}</option>)}
            </select></label>
            <label>Workflow status<select className={FIELD} value={filter} onChange={(event) => {
              setFilter(event.target.value); setCursor(""); setPage(undefined);
            }}>
              <option value="">All statuses</option>{STATES.map((state) => <option key={state} value={state}>{title(state)}</option>)}
            </select></label>
          </div>
          {page ? page.findings.length === 0 ? <p className="text-muted-ink">No tracked findings match this view.</p> :
            <ul className="divide-y divide-line rounded-md border border-line">
              {page.findings.map((item) => (
                <li key={item.finding_id} className="grid gap-2 p-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                  <div className="min-w-0">
                    <p className="font-medium">{item.title}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-ink">
                      <span className="capitalize">{item.severity}</span>
                      <span className="rounded-full bg-page px-2 py-0.5 font-medium capitalize">{title(item.workflow_status)}</span>
                      <span>Evaluation {title(item.outcome)}</span>
                    </div>
                  </div>
                  <button type="button" disabled={busy} className="inline-flex min-h-9 items-center gap-1 justify-self-start rounded-md px-2 text-sm font-medium text-sound hover:bg-page" onClick={() => void act(async () => {
                    setDetail(await getDetail(item.finding_id)); setNextState("acknowledged");
                  })}>Open finding <span className="sr-only">{item.title}</span><ChevronRight size={15} aria-hidden="true" /></button>
                </li>
              ))}
            </ul> : !error && <p role="status">Loading findings…</p>}
          {(cursor || page?.next_cursor) && <nav aria-label="Finding pages" className="flex gap-3">
            {cursor && <button className={TEXT_LINK} type="button" onClick={() => setCursor("")}>First page</button>}
            {page?.next_cursor && <button className={TEXT_LINK} type="button" onClick={() => setCursor(page.next_cursor ?? "")}>Next page</button>}
          </nav>}
        </>
      )}
      {detail && <article className="grid gap-4 rounded-lg bg-page p-4">
        <div className="flex flex-wrap justify-between gap-2">
          <h3 className="font-semibold">{detail.title}</h3>
          <button type="button" className={TEXT_LINK} onClick={() => setDetail(undefined)}>Close finding</button>
        </div>
        <p className="break-all font-mono text-sm">{detail.resource_arn}</p>
        <p className="text-sm text-muted-ink">First seen {new Date(detail.first_seen).toLocaleString()} · Last failed {new Date(detail.last_seen).toLocaleString()}</p>
        <p className="text-sm text-muted-ink">Workflow {title(detail.workflow_status)} · Evaluation {title(detail.outcome)}{detail.outcome_reason ? ` · ${title(detail.outcome_reason)}` : ""} · Rule {detail.rule_version}</p>
        {detail.workflow_status === "resolved" && detail.resolution_reason === "resource_deleted" && (
          <p className="flex items-start gap-2 rounded-md border border-line bg-surface p-3 text-sm text-sound">
            <CircleCheck size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
            Resolved because a complete inventory confirmed the resource was deleted.
          </p>
        )}
        {detail.evidence && <p>{detail.evidence}</p>}
        <p>{detail.remediation}</p>
        {detail.exception_until && EXCEPTIONS.has(detail.workflow_status) && <p>Exception through {new Date(detail.exception_until * 1000).toLocaleString()} · {detail.exception_reason}</p>}
        {canEdit && detail.workflow_status !== "resolved" && (
          <form onSubmit={update} className="grid gap-3">
            <label>Change workflow<select className={FIELD} value={nextState} onChange={(event) => setNextState(event.target.value)}>
              {STATES.filter((state) => state !== "resolved").map((state) => <option key={state} value={state}>{title(state)}</option>)}
            </select></label>
            <label>Reason<textarea className={FIELD} name="reason" maxLength={1000} required={EXCEPTIONS.has(nextState)} /></label>
            {EXCEPTIONS.has(nextState) && <label>Days until expiry<input className={FIELD} name="days" type="number" min={1} max={90} defaultValue={7} required /></label>}
            <button className={`${ACTION} justify-self-start`} disabled={busy}>Save workflow</button>
          </form>
        )}
        {canScan && <button type="button" disabled={busy} className={`${TEXT_LINK} justify-self-start`} onClick={() => void act(async () => {
          const id = detail.finding_id;
          await onboardingRequest(`${path}/${id}/verify`, { request_id: verification.current[id] ??= crypto.randomUUID() }, token);
          delete verification.current[id];
          setNotice(LOCAL_ONBOARDING ? "Sample verification queued. The fixture simulates a pass." : "Verification scan queued.");
          await onJob();
        })}>Verify finding</button>}
        {canEdit && <form className="grid gap-2" onSubmit={(event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const note = String(new FormData(form).get("comment") ?? "").trim();
          void act(async () => {
            await onboardingRequest(`${path}/${detail.finding_id}/comments`, { note }, token);
            setDetail(await getDetail(detail.finding_id));
            form.reset();
            setNotice("Comment added.");
          });
        }}>
          <label>Add a comment<textarea name="comment" className={FIELD} maxLength={1000} required /></label>
          <button className={`${ACTION} justify-self-start`} disabled={busy}>Post comment</button>
        </form>}
        <h4 className="font-semibold">History</h4>
        <ul className="grid gap-2 text-sm">
          {detail.history.map((event) => <li key={event.event_id}>
            {new Date(event.at).toLocaleString()} · {title(event.action)} · {title(event.workflow_status)} · {event.actor === "scanner" ? "Scanner" : `Member ${event.actor}`}
            {event.note && <p className="text-muted-ink">{event.note}</p>}
          </li>)}
        </ul>
      </article>}
    </section>
  );
}
