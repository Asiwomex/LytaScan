"use client";

import { useEffect, useState } from "react";
import { ArrowDownRight, ArrowUpRight, Check, ChevronRight, Cloud, Database, ListOrdered, Play, ScanLine, ShieldCheck, Square } from "lucide-react";
import { bySeverity, resourceName, SEVERITY_LABELS, serviceOf, STATUS_LABELS, type Finding } from "@/lib/findings";
import styles from "./home-hero.module.css";

const stages = [
  { title: "Inventory", detail: "Identify AWS resources", icon: Database },
  { title: "Evaluate", detail: "Read saved check results", icon: ScanLine },
  { title: "Prioritize", detail: "Rank failed checks", icon: ListOrdered },
  { title: "Verify", detail: "Inspect a finding", icon: ShieldCheck },
];

type Snapshot = { findings: Finding[]; rules: number; regions: number };

export function HomeReport({ findings, rules, regions }: Snapshot) {
  const [step, setStep] = useState(2);
  const [selected, setSelected] = useState(0);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (!running) return;
    const timer = window.setTimeout(() => {
      if (step === stages.length - 1) setRunning(false);
      else setStep(step + 1);
    }, 1100);
    return () => window.clearTimeout(timer);
  }, [running, step]);

  const resources = [...new Map(findings.map((item) => [item.resource_arn, item])).values()];
  const failed = findings.filter((item) => item.status === "fail").sort(bySeverity);
  const prioritized = [...new Map(failed.map((item) => [item.check_id, item])).values()];
  const evaluated = [...new Map(findings.map((item) => [item.check_id, item])).values()];
  const rows = (step === 0 ? resources : step === 1 ? evaluated : prioritized).slice(0, 5);
  const finding = rows[selected];
  const status = running ? (step === 3 ? "Inspecting a finding" : stages[step].title + " in progress") : stages[step].title + " selected";

  function selectStage(index: number) {
    setRunning(false);
    setSelected(0);
    setStep(index);
  }

  function togglePlayback() {
    if (running) {
      setRunning(false);
      return;
    }
    setSelected(0);
    setStep(0);
    setRunning(true);
  }

  return (
    <section data-ui className={styles.console} aria-labelledby="sample-review" id="sample-review-console">
      <header className={styles.consoleBar}>
        <div className={styles.consoleTitle}>
          <Cloud size={19} aria-hidden="true" />
          <h2 id="sample-review">AWS posture review</h2>
          <span className={styles.sample}>Sample data</span>
        </div>
        <button type="button" className={styles.replay} onClick={togglePlayback}>
          {running ? <Square size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />}
          {running ? "Stop walkthrough" : "Run walkthrough"}
        </button>
        <span className="sr-only" role="status">{status}</span>
      </header>

      <div className={styles.consoleBody}>
        <nav aria-label="Review stages" className={styles.rail}>
          <p className={styles.railLabel}>Review workflow</p>
          <ol>
            {stages.map(({ title, detail, icon: Icon }, index) => (
              <li key={title}>
                <button type="button" aria-current={step === index ? "step" : undefined}
                  onClick={() => selectStage(index)}>
                  <span className={styles.stepIcon}>
                    {index < step ? <Check size={15} aria-hidden="true" /> : <Icon size={15} aria-hidden="true" />}
                  </span>
                  <span><strong>{title}</strong><small>{detail}</small></span>
                  {index === step && <ChevronRight className={styles.stepArrow} size={15} aria-hidden="true" />}
                </button>
              </li>
            ))}
          </ol>
        </nav>

        <div className={styles.results}>
          <div className={styles.resultsTitle}>
            <h3>{["Resource inventory", "Rule evaluations", "Prioritized findings", "Finding evidence"][step]}</h3>
            <span><span className={styles.statusDot} />Read-only</span>
          </div>
          <div className={styles.metrics}>
            <span><b>{resources.length}</b> resources</span>
            <span><b>{rules}</b> rules</span>
            <span><b>{failed.length}</b> failed evaluations</span>
          </div>
          <table>
            <caption className="sr-only">Sample {stages[step].title.toLowerCase()} results</caption>
            <thead><tr><th scope="col">{step === 0 ? "Resource" : "Finding"}</th><th scope="col">Service</th><th scope="col">Result</th></tr></thead>
            <tbody>
              {rows.map((item, index) => (
                <tr key={`${item.check_id}:${item.resource_arn}:${item.region}`} data-selected={selected === index}>
                  <th scope="row">
                    <button type="button" aria-pressed={selected === index} onClick={() => setSelected(index)}>
                      <span>{step === 0 ? resourceName(item.resource_arn) : item.title}</span>
                    </button>
                  </th>
                  <td>{serviceOf(item)}</td>
                  <td><span className={styles.badge} data-severity={step > 0 && item.status === "fail" ? item.severity : undefined}>
                    {step === 0 ? "Observed" : item.status === "fail" ? SEVERITY_LABELS[item.severity] : STATUS_LABELS[item.status]}
                  </span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <aside className={styles.evidence} aria-label="Selected evidence">
          <div className={styles.evidenceTag}><ShieldCheck size={16} aria-hidden="true" /> {step === 0 ? "Resource evidence" : "Finding evidence"}</div>
          {finding && <>
            <h3>{step === 0 ? resourceName(finding.resource_arn) : finding.title}</h3>
            <dl>
              <div><dt>{step === 0 ? "Type" : "Resource"}</dt><dd><code>{step === 0 ? finding.resource_type : resourceName(finding.resource_arn)}</code></dd></div>
              <div><dt>Scope</dt><dd><code>{finding.region}</code></dd></div>
              <div><dt>{step === 0 ? "Sample scan" : "Evaluation"}</dt><dd>{step === 0 ? `${regions} regions` : STATUS_LABELS[finding.status]}</dd></div>
            </dl>
            {step !== 0 && <p>{step === 3 ? finding.remediation : finding.description}</p>}
          </>}
          <a href="#demo">Open the scan report <ArrowUpRight size={15} aria-hidden="true" /></a>
        </aside>
      </div>
      <footer className={styles.consoleFoot}>
        <span><ArrowDownRight size={15} aria-hidden="true" /> Walkthrough replays a saved fictional AWS scan.</span>
        <span>AWS Well-Architected Framework</span>
      </footer>
    </section>
  );
}
