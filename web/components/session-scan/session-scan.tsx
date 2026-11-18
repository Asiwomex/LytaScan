"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, ChevronDown, Cloud, Download, Eye, EyeOff, LoaderCircle, LogOut, Mail, Play, Printer, Search, ShieldCheck } from "lucide-react";
import { Mark } from "@/components/site/mark";
import { bySeverity, PILLARS, PILLAR_LABELS, STATUS_LABELS, type Finding } from "@/lib/findings";
import { emailDraft, makeReport, reportCsv, resultCounts, runScopeQueue, scopeKey, type Evaluation, type Inspection, type QueueControl, type ScopeState, type SessionReport, type TemporaryCredentials } from "./session-report";
import styles from "./session-scan.module.css";

type Phase = "idle" | "connecting" | "ready" | "running" | "stopping" | "complete";
type MailState = "idle" | "sending" | "sent" | "failed";
const REGION_OPTIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-east-1", "sa-east-1", "af-south-1", "me-south-1", "me-central-1", "il-central-1"];
const REQUEST_MESSAGES: Record<string, string> = {
  credentials_expired_or_invalid: "AWS could not verify these temporary credentials. Get a fresh credential set from your read-only role and try again.",
  temporary_credentials_required: "Use all three temporary AWS credential values. Long-lived access keys are not accepted.",
  temporary_role_required: "Choose temporary credentials for a read-only assumed role in your AWS access portal.",
  invalid_scope: "This check scope is unavailable. Reconnect and start a new scan.",
  invalid_regions: "Choose between one and six supported AWS regions.",
  aws_unavailable: "AWS could not complete this request. Check your connection and try again.",
  invalid_request: "Check the credential fields and selected regions, then try again.",
};

async function scanRequest<T>(body: object): Promise<T> {
  const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data) {
    const code: string = data?.error?.code ?? "request_failed";
    throw new Error(REQUEST_MESSAGES[code] ?? "The scan request could not finish. Check your temporary AWS access and try again.");
  }
  return data as T;
}

function downloadFile(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function SessionScan() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [identity, setIdentity] = useState<Inspection | null>(null);
  const [regions, setRegions] = useState(["us-east-1"]);
  const [regionToAdd, setRegionToAdd] = useState("eu-west-1");
  const [availableRegions, setAvailableRegions] = useState(REGION_OPTIONS);
  const [showSecrets, setShowSecrets] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [scopes, setScopes] = useState<ScopeState[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<SessionReport | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [visibleRows, setVisibleRows] = useState(30);
  const [email, setEmail] = useState("");
  const [emailAvailable, setEmailAvailable] = useState(false);
  const [mailState, setMailState] = useState<MailState>("idle");
  const accessInput = useRef<HTMLInputElement>(null);
  const secretInput = useRef<HTMLInputElement>(null);
  const tokenInput = useRef<HTMLInputElement>(null);
  const consentInput = useRef<HTMLInputElement>(null);
  const emailToken = useRef<string | null>(null);
  const credentials = useRef<TemporaryCredentials | null>(null);
  const pending = useRef<Promise<void> | null>(null);
  const control = useRef<QueueControl>({ stopped: false });
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    void fetch("/api/report-email", { cache: "no-store", credentials: "omit" })
      .then((response) => response.ok ? response.json() : null)
      .then((data) => { if (mounted.current) setEmailAvailable(data?.available === true); })
      .catch(() => { /* Download and draft delivery stay available. */ });
    void fetch("/api/scan", { cache: "no-store", credentials: "omit" })
      .then((response) => response.ok ? response.json() : null)
      .then((data) => {
        if (mounted.current && Array.isArray(data?.regions) && data.regions.length > 0 && data.regions.every((region: unknown) => typeof region === "string" && /^[a-z]{2}-[a-z]+-\d+$/.test(region))) setAvailableRegions(data.regions);
      }).catch(() => {});
    return () => {
      mounted.current = false; control.current.stopped = true;
      if (credentials.current) { credentials.current.access_key_id = ""; credentials.current.secret_access_key = ""; credentials.current.session_token = ""; }
      credentials.current = null; emailToken.current = null;
    };
  }, []);

  useEffect(() => {
    if (phase !== "running" && phase !== "connecting" && phase !== "stopping") return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [phase]);

  function clearCredentials() {
    if (credentials.current) {
      credentials.current.access_key_id = "";
      credentials.current.secret_access_key = "";
      credentials.current.session_token = "";
    }
    credentials.current = null;
  }

  function wipeInputs() {
    for (const input of [accessInput.current, secretInput.current, tokenInput.current]) if (input) input.value = "";
    if (consentInput.current) consentInput.current.checked = false;
  }

  async function connect(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setProblem(null); setNotice(null); setMailState("idle");
    const provided: TemporaryCredentials = { access_key_id: accessInput.current?.value.trim() ?? "", secret_access_key: secretInput.current?.value.trim() ?? "", session_token: tokenInput.current?.value.trim() ?? "" };
    if (!/^ASIA[A-Z0-9]{16}$/.test(provided.access_key_id) || provided.secret_access_key.length !== 40 || provided.session_token.length < 16) {
      setProblem("Enter all three temporary AWS credential values. The access key starts with ASIA; long-lived access keys are not accepted."); return;
    }
    if (emailAvailable && email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) { setProblem("Enter a valid report email address, or leave the email field empty."); return; }
    if (!consentInput.current?.checked) { setProblem("Confirm that you selected a read-only AWS role before connecting."); return; }
    control.current = { stopped: false };
    setPhase("connecting");
    const task = (async () => {
      try {
        const result = await scanRequest<Inspection>({ action: "inspect", credentials: provided, regions, ...(emailAvailable && email.trim() ? { report_email: email.trim().toLowerCase() } : {}) });
        if (control.current.stopped || !mounted.current) return;
        credentials.current = provided;
        emailToken.current = result.email_token ?? null;
        wipeInputs(); setIdentity(result);
        setScopes(result.scopes.map((scope) => ({ ...scope, status: "queued" })));
        setFindings([]); setReport(null); setPhase("ready");
      } catch (error) {
        if (mounted.current && !control.current.stopped) { setProblem(error instanceof Error ? error.message : "AWS connection could not be verified."); setPhase("idle"); }
      }
    })();
    pending.current = task;
    await task;
    if (pending.current === task) pending.current = null;
  }

  async function sendEmail(nextReport: SessionReport) {
    if (!email.trim() || !emailAvailable || !emailToken.current) return;
    setMailState("sending");
    try {
      const response = await fetch("/api/report-email", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "omit", cache: "no-store", body: JSON.stringify({ email: email.trim().toLowerCase(), report: nextReport, email_token: emailToken.current }) });
      const result = await response.json().catch(() => null);
      if (!response.ok || result?.sent !== true) throw new Error("delivery_failed");
      if (mounted.current) setMailState("sent");
    } catch { if (mounted.current) setMailState("failed"); }
  }

  async function run() {
    if (!identity || !credentials.current || phase !== "ready") return;
    const activeCredentials = credentials.current;
    const startedAt = new Date().toISOString();
    const nextScopes: ScopeState[] = identity.scopes.map((scope) => ({ ...scope, status: "queued" }));
    const collected: Finding[] = [];
    control.current = { stopped: false };
    setScopes([...nextScopes]); setFindings([]); setProblem(null); setNotice(null); setPhase("running");
    const task = (async () => {
      await runScopeQueue(identity.scopes,
        (scope) => scanRequest<Evaluation>({ action: "evaluate", credentials: activeCredentials, regions: identity.regions, check_id: scope.check_id, region: scope.region, account_id: identity.account_id }), control.current,
        { started: (scope) => {
            const item = nextScopes.find((item) => scopeKey(item) === scopeKey(scope));
            if (item) item.status = "running";
            if (mounted.current) setScopes(nextScopes.map((item) => ({ ...item })));
          },
          settled: (scope, result) => {
            const index = nextScopes.findIndex((item) => scopeKey(item) === scopeKey(scope));
            nextScopes[index] = result ? { ...scope, status: result.scope.status, reason_codes: result.scope.reason_codes } : { ...scope, status: "incomplete", reason_codes: ["request_failed"] };
            if (result) collected.push(...result.findings);
            if (mounted.current) { setScopes(nextScopes.map((item) => ({ ...item }))); setFindings([...collected]); }
          } });
      clearCredentials();
      if (!mounted.current || control.current.stopped) return;
      const nextReport = makeReport(identity, collected, nextScopes, startedAt, false);
      setReport(nextReport); setPhase("complete");
      setNotice("Scan finished. Temporary credentials have been cleared from this page. Download your results before signing out.");
      if (email.trim() && emailAvailable) await sendEmail(nextReport);
    })();
    pending.current = task;
    await task;
    if (pending.current === task) pending.current = null;
  }

  async function disconnect() {
    control.current.stopped = true;
    setPhase("stopping"); setNotice("Finishing requests already dispatched to AWS. No new checks will start.");
    await pending.current;
    clearCredentials(); emailToken.current = null; wipeInputs();
    if (!mounted.current) return;
    setIdentity(null); setScopes([]); setFindings([]); setReport(null); setProblem(null);
    setEmail(""); setMailState("idle"); setQuery(""); setFilter("all"); setVisibleRows(30); setShowSecrets(false);
    setNotice("Signed out. This page has cleared its temporary credentials and results. Your AWS session keeps its original expiry; you control it in AWS.");
    setPhase("idle");
  }

  const busy = phase === "connecting" || phase === "running" || phase === "stopping";
  const counts = resultCounts(findings);
  const settled = scopes.filter((scope) => scope.status === "complete" || scope.status === "incomplete").length;
  const incomplete = scopes.filter((scope) => scope.status === "incomplete").length;
  const running = scopes.filter((scope) => scope.status === "running");
  const progress = scopes.length ? Math.round((100 * settled) / scopes.length) : 0;
  const filtered = [...findings].sort(bySeverity).filter((finding) => (filter === "all" || finding.status === filter) && `${finding.title} ${finding.resource_arn} ${finding.check_id} ${finding.region}`.toLowerCase().includes(query.toLowerCase()));
  const checkTitle = (checkId: string) => identity?.checks.find((check) => check.check_id === checkId)?.title ?? checkId.replaceAll("_", " ");
  const filename = `lytascan-${identity?.account_id ?? "report"}-${report?.scan.finished_at.slice(0, 10) ?? "scan"}`;

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <Link href="/" className={styles.brand}><Mark className={styles.mark} /><span>LytaScan</span></Link>
        <span className={styles.headerLabel}>AWS scan workspace</span>
        {phase !== "idle" ? <button className={styles.disconnect} disabled={phase === "stopping"} onClick={() => void disconnect()}><LogOut size={15} />{phase === "stopping" ? "Clearing session…" : "Sign out & clear"}</button> : <Link href="/demo" className={styles.demoLink}>View sample report <ArrowRight size={15} /></Link>}
      </header>

      <main className={styles.main}>
        <div className={styles.intro}>
          <div><p className={styles.eyebrow}><span />TEMPORARY ACCESS · READ-ONLY SCANNING</p><h1>Your AWS account.<br className={styles.mobileBreak} /> One focused scan.</h1><p className={styles.introText}>Connect a temporary read-only role, run the checks, and take your results with you.</p></div>
          <div className={styles.accessNote}><ShieldCheck size={22} /><div><strong>No standing connection</strong><span>LytaScan does not save credentials or include them in reports.</span></div></div>
        </div>

        {problem && <div className={styles.alert} role="alert">{problem}</div>}
        {notice && <div className={styles.notice} role="status">{phase === "stopping" ? <LoaderCircle className={styles.spin} size={17} /> : <ShieldCheck size={17} />}<span>{notice}</span></div>}

        <div className={styles.workspace}>
          <aside className={styles.connection}>
            <div className={styles.panelHeading}><span className={styles.step}>01</span><div><h2>AWS connection</h2><p>Temporary credentials only</p></div>{identity && <span className={styles.verified}><Check size={13} />Verified</span>}</div>
            {!identity ? <form className={styles.form} onSubmit={(event) => void connect(event)} autoComplete="off">
              <details className={styles.instructions}><summary>Where do I get these values?<ChevronDown size={15} /></summary><p>In your AWS access portal, choose a role with read-only permissions, then open <strong>Command line or programmatic access</strong>. Copy its temporary access key, secret key, and session token.</p><p>Choose a read-only role such as SecurityAudit with the scanner’s required read permissions. AWS account passwords and long-lived access keys cannot be used here.</p><a href="https://docs.aws.amazon.com/singlesignon/latest/userguide/howtogetcredentials.html" target="_blank" rel="noreferrer">AWS temporary credentials guide <ArrowRight size={13} /></a></details>
              <label className={styles.field}>Temporary access key ID<input ref={accessInput} type="text" name="temporary-access-key" autoComplete="off" spellCheck={false} required pattern="ASIA[A-Z0-9]{16}" placeholder="ASIA…" disabled={busy} /><span>Starts with ASIA</span></label>
              <label className={styles.field}>Secret access key<div className={styles.secretField}><input ref={secretInput} type={showSecrets ? "text" : "password"} name="temporary-secret-key" autoComplete="off" data-lpignore="true" data-1p-ignore="true" spellCheck={false} required minLength={40} maxLength={40} placeholder="Temporary secret access key" disabled={busy} /><button type="button" onClick={() => setShowSecrets(!showSecrets)} aria-label={showSecrets ? "Hide credential values" : "Show credential values"} aria-pressed={showSecrets}>{showSecrets ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
              <label className={styles.field}>Session token<input ref={tokenInput} type={showSecrets ? "text" : "password"} name="temporary-session-token" autoComplete="off" data-lpignore="true" data-1p-ignore="true" spellCheck={false} required minLength={16} placeholder="Temporary session token" disabled={busy} /></label>
              <fieldset className={styles.regionFieldset}><legend>Regions to scan <span>Choose up to 6</span></legend><div className={styles.regionChips}>{regions.map((region) => <button type="button" key={region} disabled={busy || regions.length === 1} onClick={() => setRegions(regions.filter((item) => item !== region))} aria-label={`Remove ${region}`}>{region}<span aria-hidden="true">×</span></button>)}</div><div className={styles.addRegion}><select aria-label="Region to add" value={regionToAdd} disabled={busy || regions.length >= 6} onChange={(event) => setRegionToAdd(event.target.value)}>{availableRegions.filter((region) => !regions.includes(region)).map((region) => <option key={region}>{region}</option>)}</select><button type="button" disabled={busy || regions.length >= 6 || regions.includes(regionToAdd)} onClick={() => { setRegions([...regions, regionToAdd]); setRegionToAdd(availableRegions.find((region) => !regions.includes(region) && region !== regionToAdd) ?? "us-east-1"); }}>Add</button></div></fieldset>
              <label className={styles.consent}><input ref={consentInput} type="checkbox" required disabled={busy} /><span>I selected a read-only AWS role and authorize LytaScan to inspect this account.</span></label>
              <button className={styles.primaryButton} type="submit" disabled={busy}>{phase === "connecting" ? <LoaderCircle size={16} className={styles.spin} /> : <ShieldCheck size={16} />}{phase === "connecting" ? "Verifying AWS access…" : "Connect AWS account"}<ArrowRight size={16} /></button>
              <p className={styles.privacyNote}>Credentials are sent over HTTPS to execute your requested checks. They are kept in memory during this session and cleared after the scan or sign-out.</p>
            </form> : <div className={styles.connectedDetails}>
              <div className={styles.connectedAccount}><Cloud size={23} /><div><span>AWS account</span><strong>{identity.account_id}</strong></div></div>
              <dl><div><dt>Access</dt><dd>Temporary AWS role</dd></div><div><dt>Regions</dt><dd>{identity.regions.join(", ")}</dd></div><div><dt>Checks</dt><dd>{identity.checks.length} across six pillars</dd></div><div><dt>Credentials</dt><dd>{phase === "complete" ? "Cleared from this page" : "Memory only"}</dd></div></dl>
              <details className={styles.roleDetails}><summary>Connected role<ChevronDown size={14} /></summary><code>{identity.principal_arn}</code></details>
              <p className={styles.privacyNote}>No role or trust policy is created in your AWS account. LytaScan makes read requests using the temporary role you supplied.</p>
            </div>}
            <div className={styles.retention}><ShieldCheck size={16} /><span>Download before sign-out. Reports are cleared from this page when you leave the session.</span></div>
          </aside>

          <section className={styles.runner} aria-labelledby="scan-heading">
            <div className={styles.panelHeading}><span className={styles.step}>02</span><div><h2 id="scan-heading">Run your assessment</h2><p>All six AWS Well-Architected pillars</p></div><span className={`${styles.stateBadge} ${phase === "running" ? styles.liveBadge : ""}`}><span />{phase === "running" ? "Scanning" : phase === "complete" ? "Finished" : phase === "ready" ? "Ready" : phase === "stopping" ? "Stopping" : "Waiting for connection"}</span></div>
            <div className={styles.runnerBody}>
              <div className={styles.scanSummary}><div><h3>{phase === "complete" ? "Your assessment is ready." : phase === "running" ? "Reading your AWS configuration." : "A clear view of your AWS posture."}</h3><p>Checks evaluate configuration and available metrics. Missing permissions and incomplete reads stay visible in the report.</p></div><button type="button" className={styles.runButton} disabled={phase !== "ready"} onClick={() => void run()}>{phase === "running" ? <LoaderCircle className={styles.spin} size={17} /> : <Play size={16} />}{phase === "running" ? "Scanning…" : phase === "complete" ? "Scan finished" : "Run scan"}</button></div>
              <div className={styles.progressArea}><div><span>{phase === "running" ? "Checks in progress" : phase === "complete" ? "Scan requests settled" : "Assessment progress"}</span><strong>{settled}<span> / {scopes.length || "—"} scopes</span></strong></div><progress value={settled} max={scopes.length || 1} aria-label="Scan scope progress" /><p>{phase === "running" ? running.map((scope) => `${checkTitle(scope.check_id)} · ${scope.region}`).join(" / ") : phase === "complete" ? `${progress}% settled · ${incomplete} incomplete scopes${incomplete ? ". Review coverage before relying on the results." : "."}` : "Global checks run once. Regional checks run in each selected region."}</p></div>
              <div className={styles.pillarList}>{PILLARS.map((pillar) => { const own = scopes.filter((scope) => scope.pillar === pillar); const done = own.filter((scope) => scope.status === "complete" || scope.status === "incomplete").length; const failed = findings.filter((finding) => finding.pillar === pillar && finding.status === "fail").length; return <div key={pillar} className={styles.pillarRow}><span className={`${styles.pillarIndicator} ${own.length > 0 && done === own.length ? styles.pillarDone : ""}`}>{own.length > 0 && done === own.length ? <Check size={12} /> : <span />}</span><span>{PILLAR_LABELS[pillar]}</span><div>{failed > 0 && <span className={styles.failedMini}>{failed} failed</span>}<span className={styles.scopeCount}>{done}/{own.length || "—"}</span></div></div>; })}</div>
              <div className={styles.delivery}><div><Mail size={18} /><div><h3>Send the results to your inbox</h3><p>{emailAvailable ? "Optional. Set this before connecting; your report is emailed after the scan finishes." : "Download your report, then open an email draft and attach it."}</p></div></div><label className={styles.field}><span className={styles.srOnly}>Report recipient email, optional</span><input type="email" inputMode="email" autoComplete="off" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com (optional)" disabled={busy || identity !== null} /></label>{!emailAvailable && <span className={styles.deliveryHint}>Automatic email delivery is currently unavailable. Downloads and email drafts are available.</span>}</div>
            </div>
          </section>
        </div>

        {(findings.length > 0 || report) && <section className={styles.results} aria-labelledby="results-heading">
          <div className={styles.resultsHeading}><div><p className={styles.eyebrow}>03 / YOUR REPORT</p><h2 id="results-heading">Findings with the evidence to act.</h2></div>{report && <div className={styles.exportActions}><button onClick={() => downloadFile(`${filename}.json`, JSON.stringify(report, null, 2), "application/json")}><Download size={15} />JSON</button><button onClick={() => downloadFile(`${filename}.csv`, reportCsv(report), "text/csv;charset=utf-8")}><Download size={15} />CSV</button><button onClick={() => window.print()}><Printer size={15} />Print / PDF</button></div>}</div>
          <div className={styles.metrics}><div><span>Failed findings</span><strong>{counts.fail}</strong></div><div><span>Passed evaluations</span><strong>{counts.pass}</strong></div><div><span>Unavailable evaluations</span><strong>{counts.error + counts.unknown + counts.skipped}</strong></div><div><span>Complete scopes</span><strong>{scopes.filter((scope) => scope.status === "complete").length}<small>/{scopes.length}</small></strong></div></div>
          {report && incomplete > 0 && <p className={styles.coverageWarning} role="status">{incomplete} scopes could not complete. This report does not confirm the posture of resources those scopes could not evaluate.</p>}
          {report && <div className={styles.reportDelivery}>{emailAvailable ? <><Mail size={17} /><span>{mailState === "sending" ? "Sending your report…" : mailState === "sent" ? "Your report was sent to the requested email address." : mailState === "failed" ? "Email delivery did not finish. Your downloads are ready." : "Your report is ready to download."}</span>{mailState === "failed" && <button onClick={() => void sendEmail(report)}>Retry email</button>}</> : <><Mail size={17} /><span>Email a copy using your mail app. Download the report first and attach it to the draft.</span><a href={emailDraft(email, report)}>Open email draft <ArrowRight size={14} /></a></>}</div>}
          <div className={styles.tableToolbar}><label className={styles.search}><Search size={16} /><input value={query} onChange={(event) => { setQuery(event.target.value); setVisibleRows(30); }} placeholder="Search findings or resources" aria-label="Search scan findings" /></label><select aria-label="Filter finding results" value={filter} onChange={(event) => { setFilter(event.target.value); setVisibleRows(30); }}><option value="all">All results</option><option value="fail">Failed</option><option value="pass">Passed</option><option value="error">Could not check</option><option value="unknown">Unknown</option><option value="not_applicable">Not applicable</option></select><span>{filtered.length} findings</span></div>
          <div className={styles.tableWrap}><table className={styles.table}><thead><tr><th>Finding / evidence</th><th>Pillar</th><th>Region</th><th>Result</th></tr></thead><tbody>{filtered.slice(0, visibleRows).map((finding, index) => <tr key={`${finding.check_id}:${finding.resource_arn}:${finding.region}:${index}`}><td><details className={styles.findingDetails}><summary><ChevronDown size={13} /><strong>{finding.title}</strong></summary><div><code>{finding.resource_arn}</code><p>{finding.description}</p><h4>Suggested action</h4><p>{finding.remediation}</p>{finding.reason_code && <p className={styles.reasonCode}>Coverage reason: {finding.reason_code}</p>}</div></details><span className={styles.resourceName}>{finding.resource_arn}</span></td><td data-label="Pillar">{PILLAR_LABELS[finding.pillar]}</td><td data-label="Region"><code>{finding.region}</code></td><td data-label="Result"><span className={`${styles.resultBadge} ${finding.status === "fail" ? styles.failedBadge : finding.status === "pass" ? styles.passedBadge : styles.unavailableBadge}`}>{finding.status === "fail" ? finding.severity : STATUS_LABELS[finding.status]}</span></td></tr>)}</tbody></table>{filtered.length === 0 && <p className={styles.emptyResults}>No findings match this view.</p>}</div>{filtered.length > visibleRows && <button className={styles.showMore} onClick={() => setVisibleRows(visibleRows + 50)}>Show more findings ({filtered.length - visibleRows} remaining)</button>}
        </section>}

        <footer className={styles.footer}><span><ShieldCheck size={14} />Read-only requests. Temporary access. Results you control.</span><Link href="/">Back to LytaScan <ArrowRight size={13} /></Link></footer>
        {report && <section className={styles.printReport}><h1>LytaScan AWS assessment</h1><p>Account {report.scan.account_id} · {report.scan.finished_at}</p><p>Regions {report.scan.regions.join(", ")} · {report.execution.settled_scopes}/{report.scopes.length} scopes settled · {incomplete} incomplete</p><p>Failed {counts.fail} · Passed {counts.pass} · Unavailable {counts.error + counts.unknown + counts.skipped}</p>{report.findings.map((finding, index) => <article key={index}><h2>{finding.title} — {STATUS_LABELS[finding.status]}</h2><p>{PILLAR_LABELS[finding.pillar]} · {finding.region} · {finding.severity}</p><code>{finding.resource_arn}</code><p>{finding.description}</p><p><strong>Suggested action:</strong> {finding.remediation}</p>{finding.reason_code && <p>Coverage reason: {finding.reason_code}</p>}</article>)}</section>}
      </main>
    </div>
  );
}
