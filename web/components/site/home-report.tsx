"use client";

import { useState, type CSSProperties } from "react";
import { ArrowUpRight, ClipboardList } from "lucide-react";
import { SEVERITY_LABELS, type Pillar, type Severity } from "@/lib/findings";
import { verdict } from "@/lib/score";
import styles from "./home.module.css";

export type ReportPillar = {
  pillar: Pillar;
  label: string;
  score: number | null;
  failed: number;
  passed: number;
  cells: (Severity | "pass")[];
  priority?: { severity: Severity; title: string };
};

export function HomeReport({ score, pillars }: { score: number | null; pillars: ReportPillar[] }) {
  const [active, setActive] = useState(pillars[0].pillar);
  const selected = pillars.find((pillar) => pillar.pillar === active) ?? pillars[0];

  return (
    <div data-ui className={styles.report} data-home-enter>
      <div className={styles.reportHeader}>
        <span><ClipboardList size={17} aria-hidden="true" /> Posture report</span>
        <span>Fictional account</span>
      </div>
      <div className={styles.scoreRow}>
        <div><p>Posture score</p><strong>{score ?? "—"}<span> / 100</span></strong></div>
        <span>{verdict(score)}</span>
      </div>
      <div className={styles.reportPillars} aria-label="Sample pillar scores">
        {pillars.map((pillar) => <button key={pillar.pillar} type="button" aria-pressed={pillar.pillar === active}
          onClick={() => setActive(pillar.pillar)} className={styles.pillarButton}>
          <span aria-hidden="true" className={styles.blocks}>
            {pillar.cells.map((status, index) => <span key={index} data-result={status} className={styles.block}
              style={{ "--block-index": index } as CSSProperties} />)}
          </span>
          <span className={styles.pillarLabel}>{pillar.label}</span>
          <span className={styles.pillarScore}>{pillar.score ?? "—"}<span className="sr-only"> out of 100</span></span>
        </button>)}
      </div>
      <div className={styles.reportFinding} aria-live="polite">
        <div className={styles.findingInfo}>
          <p>{selected.label} · {selected.failed} failed · {selected.passed} passed</p>
          <strong>{selected.priority?.title ?? "No failed checks"}</strong>
        </div>
        {selected.priority && <span className={styles.severity} data-result={selected.priority.severity}>
          {SEVERITY_LABELS[selected.priority.severity]}
        </span>}
      </div>
      <a className={styles.reportLink} href="#demo">Explore this report <ArrowUpRight size={15} aria-hidden="true" /></a>
    </div>
  );
}
