"use client";

import { useEffect, useState, type FormEvent } from "react";
import { ACTION, FIELD, TEXT_LINK } from "./onboarding-auth";
import { onboardingRequest, type Connection } from "@/lib/onboarding";

type Member = { member_id: string; email: string | null; role: string; allowed_account: string | null; is_self: boolean };
const ROLES = ["viewer", "engineer", "security_analyst", "finance_analyst", "administrator"];
const label = (role: string) => role.replaceAll("_", " ");

export function TeamMembers({ orgId, token, role, connections, onTransfer }: {
  orgId: string; token: string; role: string; connections: Connection[]; onTransfer: () => void;
}) {
  const [members, setMembers] = useState<Member[]>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState(0);
  const [confirm, setConfirm] = useState<{ member: Member; transfer: boolean }>();
  const path = `/v1/orgs/${orgId}/members`;

  useEffect(() => {
    let cancelled = false;
    onboardingRequest<Member[]>(path, undefined, token)
      .then((items) => { if (!cancelled) setMembers(items); })
      .catch((problem: Error) => { if (!cancelled) setError(problem.message); });
    return () => { cancelled = true; };
  }, [path, token, version]);

  async function act(action: () => Promise<void>, message: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setConfirm(undefined);
      setVersion((value) => value + 1);
      setNotice(message);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Try again.");
    } finally {
      setBusy(false);
    }
  }

  function save(event: FormEvent<HTMLFormElement>, member: Member) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    void act(async () => {
      await onboardingRequest(`${path}/${member.member_id}`, {
        role: fields.get("role"), allowed_account: fields.get("account") || null,
      }, token, "PATCH");
    }, "Membership updated.");
  }

  return (
    <section className="panel grid gap-4 p-4 text-ink sm:p-5">
      <h2 className="text-lg font-semibold">Team members</h2>
      {error && <p role="alert" className="text-critical">{error}</p>}
      {notice && <p role="status" className="text-sound">{notice}</p>}
      {!members && (error
        ? <button type="button" className={`${TEXT_LINK} justify-self-start`} onClick={() => { setError(""); setVersion((value) => value + 1); }}>Retry loading members</button>
        : <p role="status">Loading members…</p>)}
      <ul className="divide-y divide-line">
        {members?.map((member) => {
          const name = member.email ?? (member.is_self ? "You" : "Organization owner");
          const editable = !member.is_self && member.role !== "owner" && (role === "owner" || member.role !== "administrator");
          return (
            <li key={member.member_id} className="grid gap-3 py-3">
              <p className="break-all font-medium">{name} · {label(member.role)}</p>
              {editable && (
                <form key={`${member.role}:${member.allowed_account}`} onSubmit={(event) => save(event, member)} className="flex flex-wrap items-end gap-3">
                  <label>Member role<select className={FIELD} name="role" defaultValue={member.role}>
                    {ROLES.filter((value) => value !== "administrator" || role === "owner").map((value) => <option key={value} value={value}>{label(value)}</option>)}
                  </select></label>
                  <label>Account grant<select className={FIELD} name="account" defaultValue={member.allowed_account ?? ""}>
                    <option value="">No account selected</option>
                    {connections.map((item) => <option key={item.account_connection_id} value={item.account_connection_id}>{item.name}</option>)}
                  </select></label>
                  <button className={ACTION} disabled={busy}>Save membership</button>
                  <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setConfirm({ member, transfer: false })}>Remove member</button>
                  {role === "owner" && member.role === "administrator" &&
                    <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setConfirm({ member, transfer: true })}>Transfer ownership</button>}
                </form>
              )}
              {confirm?.member.member_id === member.member_id && (
                <div className="flex flex-wrap items-center gap-3 rounded-md bg-page p-3">
                  <p>{confirm.transfer ? `Make ${name} the owner? Your role will become administrator.` : `Remove ${name} from this organization?`}</p>
                  <button type="button" className={ACTION} disabled={busy} onClick={() => void act(async () => {
                    const memberPath = `${path}/${member.member_id}`;
                    if (confirm.transfer) {
                      await onboardingRequest(`${memberPath}/transfer-ownership`, {}, token);
                      onTransfer();
                    } else {
                      await onboardingRequest(memberPath, undefined, token, "DELETE");
                    }
                  }, confirm.transfer ? "Ownership transferred." : "Member removed.")}>Confirm {confirm.transfer ? "transfer" : "removal"}</button>
                  <button type="button" className={TEXT_LINK} disabled={busy} onClick={() => setConfirm(undefined)}>Cancel</button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
