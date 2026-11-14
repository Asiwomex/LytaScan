"use client";

import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";
import { Activity, ArrowUpRight, ChevronDown, ChevronRight, Cloud, FlaskConical, LayoutGrid, LogOut, ShieldAlert, Users } from "lucide-react";

import { Mark } from "@/components/site/mark";
import { LOCAL_ONBOARDING } from "@/lib/backend";
import type { Organization } from "@/lib/onboarding";
import styles from "./workspace-shell.module.css";

const SECTIONS = [
  { id: "scan-jobs", label: "Scans", icon: Activity },
  { id: "tracked-findings", label: "Findings", icon: ShieldAlert },
  { id: "aws-connections", label: "Connections", icon: Cloud },
  { id: "workspace-team", label: "Team", icon: Users },
] as const;

export function WorkspaceShell({ children, organizations, selected, connecting, signedIn, email, onSwitch, onLeave }: {
  children: ReactNode;
  organizations: Organization[];
  selected?: Organization;
  connecting: boolean;
  signedIn: boolean;
  email?: string | null;
  onSwitch: (id: string) => void;
  onLeave: () => void;
}) {
  const manager = selected && ["owner", "administrator"].includes(selected.role);
  const [active, setActive] = useState("scan-jobs");
  const shortName = selected?.name.slice(0, 2).toUpperCase() || "LS";

  useEffect(() => {
    const readHash = () => {
      const section = window.location.hash.slice(1);
      if (SECTIONS.some((item) => item.id === section)) setActive(section);
    };
    const readInitial = window.setTimeout(readHash, 0);
    window.addEventListener("hashchange", readHash);
    return () => {
      window.clearTimeout(readInitial);
      window.removeEventListener("hashchange", readHash);
    };
  }, []);

  return (
    <div className={styles.shell}>
      <a className={styles.skip} href="#workspace-content">Skip to workspace</a>
      <aside className={styles.sidebar}>
        <Link href="/" className={styles.brand}>
          <Mark className={styles.brandMark} sound="var(--console-accent)" />
          <span>LytaScan</span>
        </Link>
        {organizations.length > 0 && (
          <label className={styles.orgPicker}>
            <span className={styles.avatar} aria-hidden="true">{shortName}</span>
            <span className={styles.orgField}>
              <span className="sr-only">Organization</span>
              <select value={selected?.organization_id ?? ""} onChange={(event) => onSwitch(event.target.value)}>
                {organizations.map((item) => <option key={item.organization_id} value={item.organization_id}>{item.name}</option>)}
              </select>
              {selected && <span className={styles.role}>{selected.role.replaceAll("_", " ")}</span>}
            </span>
            <ChevronDown aria-hidden="true" size={14} />
          </label>
        )}
        <nav className={styles.nav} aria-label="Workspace">
          {connecting ? (
            <Link href={selected ? `/organizations?org=${selected.organization_id}` : "/organizations"}>
              <LayoutGrid aria-hidden="true" size={17} /> Organizations
            </Link>
          ) : selected?.role !== "finance_analyst" && selected ? SECTIONS
            .filter((item) => manager || (item.id !== "aws-connections" && item.id !== "workspace-team"))
            .map(({ id, label, icon: Icon }) => (
              <a key={id} href={`#${id}`} aria-current={active === id ? "location" : undefined} onClick={() => setActive(id)}>
                <Icon aria-hidden="true" size={17} /> {label}
              </a>
            )) : (
            <a href="#workspace-content" aria-current="location"><LayoutGrid aria-hidden="true" size={17} /> Overview</a>
          )}
        </nav>
        <div className={styles.sidebarFooter}>
          <Link href="/demo" className={styles.externalLink}>
            <FlaskConical aria-hidden="true" size={16} /> Demo <ArrowUpRight aria-hidden="true" size={14} className="ml-auto" />
          </Link>
        </div>
      </aside>
      <div className={styles.main}>
        <header className={styles.topbar}>
          <div className={styles.breadcrumb}>
            <span>Workspace</span>
            <ChevronRight aria-hidden="true" size={13} />
            <span aria-current="page">{connecting ? "Connect account" : "Organizations"}</span>
          </div>
          <div className={styles.topbarTools}>
            {LOCAL_ONBOARDING && <span className={styles.environment}><span aria-hidden="true" /> Local preview</span>}
            {signedIn && (
              <button type="button" className={styles.signOut} title={email ?? undefined} onClick={onLeave}>
                <LogOut aria-hidden="true" size={15} /> Sign out
              </button>
            )}
          </div>
        </header>
        <main className={styles.content} id="workspace-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
