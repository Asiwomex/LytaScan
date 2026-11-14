"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { ACTION, FIELD, TEXT_LINK } from "./onboarding-auth";
import { OrganizationOperations } from "./organization-operations";
import { WorkspaceShell } from "./workspace-shell";
import { currentSession, forgetSession, signOut, type Session } from "@/lib/auth";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import {
  OnboardingError, REGIONS, onboardingRequest, type Connection, type ConnectionSetup, type Organization,
} from "@/lib/onboarding";

export function OrganizationWorkspace({ connecting = false }: { connecting?: boolean }) {
  const [session, setSession] = useState<Session | null>();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [orgId, setOrgId] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [inviteToken, setInviteToken] = useState("");
  const [connectionVersion, setConnectionVersion] = useState(0);
  const createRequest = useRef<{ name: string; id: string } | null>(null);
  const enabled = LOCAL_ONBOARDING || ACCOUNTS_ONLINE;
  const selected = orgs.find((org) => org.organization_id === orgId);

  const report = useCallback((problem: unknown) => {
    if (problem instanceof OnboardingError && problem.status === 401) {
      forgetSession();
      setSession(null);
    }
    setError(problem instanceof Error ? problem.message : "Try again.");
  }, []);

  useEffect(() => {
    if (!enabled) return;
    const active = currentSession();
    let cancelled = false;
    function readInvite() {
      const token = new URLSearchParams(window.location.hash.slice(1)).get("invite");
      if (token) {
        sessionStorage.setItem("pillarscan.team-invite", token);
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
      setInviteToken(sessionStorage.getItem("pillarscan.team-invite") ?? "");
    }
    queueMicrotask(() => {
      if (cancelled) return;
      setSession(active);
      readInvite();
    });
    window.addEventListener("hashchange", readInvite);
    if (active) {
      onboardingRequest<Organization[]>("/v1/orgs", undefined, active.accessToken)
        .then((items) => {
          if (cancelled) return;
          setOrgs(items);
          const requested = new URLSearchParams(window.location.search).get("org");
          setOrgId(items.find((item) => item.organization_id === requested)?.organization_id ?? items[0]?.organization_id ?? "");
          setLoaded(true);
        })
        .catch((problem) => { if (!cancelled) report(problem); });
    }
    return () => {
      cancelled = true;
      window.removeEventListener("hashchange", readInvite);
    };
  }, [enabled, loadAttempt, report]);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session) return;
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "").trim();
    if (createRequest.current?.name !== name) createRequest.current = { name, id: crypto.randomUUID() };
    setBusy(true);
    setError("");
    try {
      const org = await onboardingRequest<Organization>("/v1/orgs", {
        name, request_id: createRequest.current.id,
      }, session.accessToken);
      setOrgs((current) => [...current.filter((item) => item.organization_id !== org.organization_id), org]);
      setOrgId(org.organization_id);
      createRequest.current = null;
      form.reset();
    } catch (problem) {
      report(problem);
    } finally {
      setBusy(false);
    }
  }

  async function leave() {
    if (!LOCAL_ONBOARDING) return signOut();
    if (!session) return;
    try {
      await onboardingRequest("/local/sign-out", {}, session.accessToken);
    } catch (problem) {
      report(problem);
    } finally {
      forgetSession();
      setSession(null);
      setOrgs([]);
      setOrgId("");
    }
  }

  async function acceptInvite() {
    if (!session) return;
    setBusy(true);
    setError("");
    try {
      const joined = await onboardingRequest<{ organization_id: string }>("/v1/orgs/invites/accept",
        { token: inviteToken }, session.accessToken);
      sessionStorage.removeItem("pillarscan.team-invite");
      window.location.replace(`/organizations?org=${joined.organization_id}`);
    } catch (problem) {
      report(problem);
    } finally {
      setBusy(false);
    }
  }

  function selectOrganization(id: string) {
    setOrgId(id);
    const url = new URL(window.location.href);
    url.searchParams.set("org", id);
    window.history.replaceState(null, "", url);
  }

  return (
    <WorkspaceShell organizations={orgs} selected={selected} connecting={connecting} signedIn={Boolean(session)}
      email={session?.email} onSwitch={selectOrganization} onLeave={() => void leave()}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[clamp(1.55rem,3vw,2.05rem)] leading-tight font-semibold tracking-tight">{connecting ? "Connect an AWS account" : selected?.name ?? "Organizations"}</h1>
          {selected && !connecting && <p className="mt-1 text-sm text-muted-ink">AWS posture workspace</p>}
        </div>
        {!!session && loaded && !connecting && orgId && (
          <details className="group min-w-0 sm:w-auto">
            <summary className="inline-flex min-h-10 cursor-pointer list-none items-center rounded-md border border-line bg-surface px-3 font-medium hover:bg-page [&::-webkit-details-marker]:hidden">
              New organization
            </summary>
            <form className="panel mt-2 grid gap-3 p-4" onSubmit={create}>
              <label>Organization name<input className={FIELD} name="name" required maxLength={80} /></label>
              <button className={`${ACTION} justify-self-start`} disabled={busy}>{busy ? "Creating…" : "Create organization"}</button>
            </form>
          </details>
        )}
      </div>
      {error && <p className="mt-4 rounded-md border border-line bg-surface p-3 text-critical" role="alert">{error}</p>}
      {inviteToken && session && <section className="panel mt-4 flex flex-wrap items-center gap-3 p-4 text-ink">
        <p>Accept the invitation as {session.email ?? "your signed-in account"}.</p>
        <button type="button" className={ACTION} disabled={busy} onClick={() => void acceptInvite()}>Accept invitation</button>
        <button type="button" className={TEXT_LINK} onClick={() => {
          sessionStorage.removeItem("pillarscan.team-invite");
          setInviteToken("");
        }}>Dismiss</button>
      </section>}
      {!enabled ? (
        <p className="mt-5 text-muted-ink">The account service is currently offline.</p>
      ) : session === undefined ? (
        <p className="mt-5 text-muted-ink" role="status">Checking your session…</p>
      ) : !session ? (
        <Link href="/sign-in" className={`${ACTION} mt-5`}>Sign in</Link>
      ) : !loaded ? (
        error ? <button type="button" className="mt-4 underline" onClick={() => { setError(""); setLoadAttempt((value) => value + 1); }}>Retry loading organizations</button>
          : <p className="mt-5 text-muted-ink" role="status">Loading organizations…</p>
      ) : (
        <div className="mt-6 grid gap-4">
          {!orgId && (
            <form className="panel grid max-w-xl gap-3 p-4 text-ink sm:p-5" onSubmit={create}>
              <h2 className="text-lg font-semibold">Create an organization</h2>
              <label>Organization name<input className={FIELD} name="name" required maxLength={80} /></label>
              <button className={`${ACTION} justify-self-start`} disabled={busy}>{busy ? "Creating…" : "Create organization"}</button>
            </form>
          )}
          {connecting && selected && ["owner", "administrator"].includes(selected.role) && (
            <Connections key={orgId} orgId={orgId} token={session.accessToken}
              connecting={connecting} onChanged={() => setConnectionVersion((value) => value + 1)}
              onUnauthorized={() => { forgetSession(); setSession(null); }} />
          )}
          {!connecting && selected && selected.role !== "finance_analyst" && (
            <OrganizationOperations key={`${orgId}:${connectionVersion}:${selected.role}`} orgId={orgId} role={selected.role} token={session.accessToken}
              connectionPanel={["owner", "administrator"].includes(selected.role) && (
                <Connections key={orgId} orgId={orgId} token={session.accessToken} connecting={false}
                  onChanged={() => setConnectionVersion((value) => value + 1)}
                  onUnauthorized={() => { forgetSession(); setSession(null); }} />
              )}
              onTransfer={() => setOrgs((items) => items.map((item) => item.organization_id === orgId ? { ...item, role: "administrator" } : item))} />
          )}
          {selected?.role === "finance_analyst" && <p className="text-muted-ink">Cloud cost views are pending.</p>}
        </div>
      )}
    </WorkspaceShell>
  );
}

function Connections({ orgId, token, connecting, onUnauthorized, onChanged }: {
  orgId: string; token: string; connecting: boolean; onUnauthorized: () => void; onChanged: () => void;
}) {
  const [items, setItems] = useState<Connection[]>([]);
  const [setup, setSetup] = useState<ConnectionSetup | null>(null);
  const [role, setRole] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [completedSetup, setCompletedSetup] = useState(false);
  const [disconnecting, setDisconnecting] = useState<Connection>();
  const [cleanupPending, setCleanupPending] = useState<Connection>();
  const path = `/v1/orgs/${orgId}/connections`;
  const unauthorized = useRef(onUnauthorized);

  useEffect(() => { unauthorized.current = onUnauthorized; }, [onUnauthorized]);

  const report = useCallback((problem: unknown) => {
    if (problem instanceof OnboardingError && problem.status === 401) unauthorized.current();
    setError(problem instanceof Error ? problem.message : "Try again.");
  }, []);

  useEffect(() => {
    let cancelled = false;
    onboardingRequest<Connection[]>(path, undefined, token)
      .then((connections) => {
        if (!cancelled) {
          setItems(connections);
          setLoaded(true);
        }
      })
      .catch((problem) => { if (!cancelled) report(problem); });
    return () => { cancelled = true; };
  }, [path, token, loadAttempt, report]);

  async function act(operation: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await operation();
    } catch (problem) {
      report(problem);
    } finally {
      setBusy(false);
    }
  }

  function upsert(item: Connection) {
    setItems((current) => [...current.filter((value) => value.aws_account_id !== item.aws_account_id), item]);
  }

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    await act(async () => {
      const item = await onboardingRequest<ConnectionSetup>(path, {
        name: fields.get("name"),
        aws_account_id: fields.get("aws_account_id"),
        region: fields.get("region"),
        read_access_consent: fields.get("consent") === "on",
      }, token);
      setSetup(item);
      setCompletedSetup(false);
      setRole("");
      upsert(item);
    });
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!setup) return;
    await act(async () => {
      try {
        const item = await onboardingRequest<Connection>(`${path}/${setup.aws_account_id}/verify`, {
          role_arn: role.trim(),
        }, token);
        upsert(item);
        setSetup(null);
        setCompletedSetup(true);
        onChanged();
        setNotice(LOCAL_ONBOARDING ? "Simulated verification passed." : "AWS account verified.");
      } catch (problem) {
        if (problem instanceof OnboardingError && problem.status === 422) {
          const updated = await onboardingRequest<Connection[]>(path, undefined, token);
          setItems(updated);
        }
        throw problem;
      }
    });
  }

  async function disconnect(item: Connection) {
    await act(async () => {
      const result = await onboardingRequest<{ stack_name: string; cleanup_queued: boolean }>(
        `${path}/${item.aws_account_id}/disconnect`, { connection_id: item.account_connection_id }, token,
      );
      setItems((current) => current.filter((entry) => entry.account_connection_id !== item.account_connection_id));
      setDisconnecting(undefined);
      setCleanupPending(result.cleanup_queued ? undefined : item);
      if (setup?.account_connection_id === item.account_connection_id) setSetup(null);
      onChanged();
      setNotice(LOCAL_ONBOARDING ? "Sample connection disconnected." :
        `Connection disconnected. Remove the ${result.stack_name} stack in AWS to revoke the role.`);
    });
  }

  return (
    <section id="aws-connections" aria-labelledby="connections-heading" className="panel grid gap-4 p-4 text-ink sm:p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="connections-heading" className="text-lg font-semibold">AWS connections</h2>
        {!connecting && <Link href={`/accounts/connect?org=${orgId}`} className={TEXT_LINK}>Connect an account</Link>}
      </div>
      {error && <p role="alert" className="text-critical">{error}</p>}
      {notice && <p role="status" className="text-sound">{notice}</p>}
      {cleanupPending && <button type="button" className={`${TEXT_LINK} justify-self-start`} disabled={busy}
        onClick={() => void disconnect(cleanupPending)}>Retry scan history cleanup</button>}
      {!loaded && (error
        ? <button className={`${TEXT_LINK} justify-self-start`} onClick={() => { setError(""); setLoadAttempt((value) => value + 1); }}>Retry loading connections</button>
        : <p role="status" className="text-muted-ink">Loading connections…</p>)}
      {loaded && items.length === 0 && <p className="text-muted-ink">This organization has no AWS connections yet.</p>}
      {items.length > 0 && (
        <ul className="divide-y divide-line rounded-lg border border-line">
          {items.map((item) => (
            <li key={item.account_connection_id} className="flex flex-wrap items-center justify-between gap-3 p-3">
              <div>
                <p className="font-semibold">{item.name}</p>
                <p className="text-sm text-muted-ink">{item.aws_account_id} · {item.region} · {item.status}</p>
              </div>
              <div className="flex flex-wrap gap-3">
              <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => void act(async () => {
                setSetup(await onboardingRequest<ConnectionSetup>(`${path}/${item.aws_account_id}/setup`, undefined, token));
                setRole("");
              })}>{item.status === "verified" ? "Verify again" : "Continue setup"}</button>
              <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setDisconnecting(item)}>Disconnect</button>
              </div>
              {disconnecting?.account_connection_id === item.account_connection_id && (
                <div className="flex w-full flex-wrap items-center gap-3 rounded-md bg-page p-3">
                  <p>Disconnect {item.name} and remove its organization scan history?</p>
                  <button type="button" className={ACTION} disabled={busy} onClick={() => void disconnect(item)}>Confirm disconnect</button>
                  <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setDisconnecting(undefined)}>Cancel</button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {connecting && loaded && !setup && !completedSetup && (
        <form onSubmit={connect} className="grid gap-3">
          <h3 className="font-semibold">1. Account details</h3>
          {LOCAL_ONBOARDING && <p className="text-sm text-muted-ink">Use 111122223333 to simulate a successful AWS verification.</p>}
          <label>Account name<input className={FIELD} name="name" required maxLength={80} /></label>
          <label>AWS account ID<input className={FIELD} name="aws_account_id" inputMode="numeric" pattern="[0-9]{12}" maxLength={12} required /></label>
          <label>Verification region<select className={FIELD} name="region">{REGIONS.map((region) => <option key={region}>{region}</option>)}</select></label>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" name="consent" required className="mt-1" />I authorize LytaScan to use a read-only role to verify AWS account metadata.</label>
          <button className={`${ACTION} justify-self-start`} disabled={busy}>{busy ? "Saving…" : "Continue to role setup"}</button>
        </form>
      )}
      {connecting && completedSetup && !setup && (
        <button type="button" className={`${TEXT_LINK} justify-self-start`} onClick={() => setCompletedSetup(false)}>
          Connect another account
        </button>
      )}
      {setup && (
        <form onSubmit={verify} className="grid gap-3 rounded-lg bg-page p-4">
          <h3 className="font-semibold">2. Set up the read-only role</h3>
          {setup.launch_url ? (
            <p className="text-sm text-muted-ink">In the AWS account above, <a className={TEXT_LINK} href={setup.launch_url} target="_blank" rel="noopener noreferrer">open the CloudFormation template</a>. After the stack completes, copy the RoleArn from its Outputs tab.</p>
          ) : <p className="text-sm text-muted-ink">Copy the sample role ARN below to test verification locally.</p>}
          <code className="break-all text-sm">{setup.role_arn}</code>
          <label>Role ARN<input className={FIELD} required maxLength={100} value={role} onChange={(event) => setRole(event.target.value)} /></label>
          <div className="flex flex-wrap items-center gap-3">
            <button className={ACTION} disabled={busy}>{busy ? "Verifying…" : "Verify connection"}</button>
            <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setSetup(null)}>Close setup</button>
          </div>
        </form>
      )}
    </section>
  );
}
