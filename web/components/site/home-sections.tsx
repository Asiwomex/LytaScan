import { readFileSync } from "node:fs";
import path from "node:path";
import Link from "next/link";
import { ArrowDown, ArrowRight, ArrowUpRight, Terminal } from "lucide-react";

import { Mark } from "@/components/site/mark";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { PILLARS, PILLAR_LABELS, type Pillar } from "@/lib/findings";
import { AUTHOR_URL, LYTAWORKS_URL, REPO_URL } from "@/lib/links";
import styles from "./home-sections.module.css";

const SAMPLE_RULES: Record<Pillar, string> = {
  security: "ec2_imdsv2_required",
  reliability: "dynamodb_deletion_protection",
  cost: "ebs_unattached_volume",
  operational_excellence: "cloudwatch_alarm_actions",
  performance_efficiency: "rds_free_storage_pressure",
  sustainability: "s3_incomplete_multipart_cleanup",
};

/** The Python registry exports this catalog alongside the repository source. */
function scannerRules() {
  const catalog = readFileSync(path.join(process.cwd(), "..", "docs", "check-catalog.md"), "utf8");
  return Array.from(catalog.matchAll(/^\| `([^`]+)`<br>(.*?) \| ([^|]+) \|/gm), ([, id, name, pillar]) => ({
    id,
    name: name.replace(/ \(\[AWS documentation\]\(.+\)\)$/, "").replaceAll("\\|", "|"),
    pillar,
  }));
}

export function HomeChecks() {
  const rules = scannerRules();
  const groups = PILLARS.map((pillar) => {
    const label = PILLAR_LABELS[pillar];
    const checks = rules.filter((rule) => rule.pillar === label);
    return { label, checks, sample: checks.find((rule) => rule.id === SAMPLE_RULES[pillar]) ?? checks[0] };
  });

  return (
    <section id="checks" aria-labelledby="home-checks-title" className={styles.checks}>
      <div className={styles.wrap}>
        <div className={styles.sectionHeading}>
          <h2 id="home-checks-title" data-home-enter>Six pillars. {rules.length} checks.</h2>
          <p data-home-enter>See what the scanner looks for across the AWS Well-Architected Framework.</p>
        </div>
        <table className={styles.checkTable} data-home-enter>
          <caption className="sr-only">Scanner rules grouped by AWS Well-Architected pillar</caption>
          <thead>
            <tr><th scope="col">Pillar</th><th scope="col">Checks</th><th scope="col">Example check</th></tr>
          </thead>
          <tbody>
            {groups.map(({ label, checks, sample }) => (
              <tr key={label}>
                <th scope="row">{label}</th>
                <td className={styles.checkCount}>{checks.length}</td>
                <td>{sample?.name}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <details className={styles.catalog}>
          <summary>Browse the full check catalog <ArrowDown size={17} aria-hidden="true" /></summary>
          <div className={styles.catalogGroups}>
            {groups.map(({ label, checks }) => (
              <div key={label}>
                <h3>{label}</h3>
                <ul>{checks.map((rule) => <li key={rule.id}>{rule.name}</li>)}</ul>
              </div>
            ))}
          </div>
        </details>
      </div>
    </section>
  );
}

const WORKFLOW = [
  { title: "Connect with a read-only role", body: "Authorize a role for the account you want to review. LytaScan reads configuration and metrics using the permissions you grant." },
  { title: "Run a scoped scan", body: "Choose a full, quick or single-pillar scan in the workspace. Track progress by check and region as evaluations finish." },
  { title: "Review and verify findings", body: "Open a finding to see the affected resource and suggested fix. After a change, rerun the check to verify it." },
];

export function HomeWorkflow() {
  return (
    <section id="how-it-works" aria-labelledby="home-workflow-title" className={styles.workflow}>
      <div className={`${styles.wrap} ${styles.workflowGrid}`}>
        <div className={styles.workflowCopy}>
          <h2 id="home-workflow-title" data-home-enter>From scan to fix.</h2>
          <ol className={styles.steps}>
            {WORKFLOW.map(({ title, body }) => (
              <li key={title} data-home-enter>
                <h3>{title}</h3>
                <p>{body}</p>
              </li>
            ))}
          </ol>
        </div>
        <figure data-ui data-home-enter className={styles.terminal}>
          <figcaption><Terminal size={18} aria-hidden="true" /> Run from your terminal</figcaption>
          <pre><code>python -m scanner --report-version 2 --regions us-east-1</code></pre>
          <p>The CLI uses your configured AWS credentials and writes a JSON report. Use <code>--catalog</code> to browse the rules without connecting to AWS.</p>
          <a href={`${REPO_URL}#readme`}>Read the CLI setup <ArrowUpRight size={17} aria-hidden="true" /></a>
        </figure>
      </div>
    </section>
  );
}

export function HomeStatus() {
  const workspaceStatus = LOCAL_ONBOARDING
    ? "Local preview uses a fictional AWS account and simulated scan results."
    : ACCOUNTS_ONLINE
      ? "Sign in to use the organization workspace and connect a supported AWS account."
      : "Hosted account connections are currently paused. The public demo runs on included sample data.";

  return (
    <section id="status" aria-labelledby="home-status-title" className={styles.status}>
      <div className={`${styles.wrap} ${styles.statusGrid}`}>
        <h2 id="home-status-title" data-home-enter>Built in the open.</h2>
        <div data-home-enter>
          <p>LytaScan is an independent portfolio project by Asiwome Boateng. The scanner is written in Python and the infrastructure is managed with Terraform.</p>
          <p>{workspaceStatus}</p>
          <a className={styles.inlineLink} href={REPO_URL}>Explore the source on GitHub <ArrowUpRight size={18} aria-hidden="true" /></a>
        </div>
      </div>
    </section>
  );
}

export function HomeFooter() {
  return (
    <footer className={styles.footer}>
      <div className={styles.wrap}>
        <div className={styles.footerTop} data-home-enter>
          <p>Explore a sample AWS posture report.</p>
          <Link href="/demo" className={styles.footerAction}>Open the demo <ArrowRight size={19} aria-hidden="true" /></Link>
        </div>
        <Link className={styles.footerBrand} href="/#top" aria-label="LytaScan, back to top" data-home-enter>
          <Mark className={styles.footerMark} sound="var(--support-accent)" /> LytaScan
        </Link>
        <div className={styles.footerMeta}>
          <p>Built by <a href={AUTHOR_URL}>Asiwome Boateng</a><br />Powered by <a href={LYTAWORKS_URL}>LytaWorks</a></p>
          <p>LytaScan is an independent project. AWS and its service names are trademarks of Amazon.com, Inc. or its affiliates.</p>
          <a href={REPO_URL} className={styles.inlineLink}>Source code <ArrowUpRight size={16} aria-hidden="true" /></a>
        </div>
      </div>
    </footer>
  );
}
