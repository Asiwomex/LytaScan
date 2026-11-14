import Link from "next/link";
import { ArrowDown, ArrowUpRight } from "lucide-react";

import { Dashboard } from "@/components/dashboard";
import { HomeHeader } from "@/components/site/home-header";
import { HomeMotion } from "@/components/site/home-motion";
import { HomeReport } from "@/components/site/home-report";
import { HomeChecks, HomeFooter, HomeStatus, HomeWorkflow } from "@/components/site/home-sections";
import styles from "@/components/site/home.module.css";
import { bySeverity, PILLAR_LABELS } from "@/lib/findings";
import { loadScans } from "@/lib/scans";
import { postureScore, summarisePillars } from "@/lib/score";

export default function Home() {
  const scans = loadScans();
  const findings = scans[0].report.findings;
  const pillars = summarisePillars(findings).map((pillar) => {
    const own = findings.filter((finding) => finding.pillar === pillar.pillar).sort(bySeverity);
    const priority = own.find((finding) => finding.status === "fail");
    const cells = own.flatMap((finding) => finding.status === "fail" ? [finding.severity] :
      finding.status === "pass" ? ["pass" as const] : []);
    return { ...pillar, label: PILLAR_LABELS[pillar.pillar], cells,
      priority: priority && { title: priority.title, severity: priority.severity } };
  });

  return (
    <div id="top" className={styles.home}>
      <HomeHeader />
      <main id="home-main">
        <section className={styles.hero} aria-labelledby="home-title">
          <div className={`${styles.shell} ${styles.heroGrid}`}>
            <div className={styles.heroCopy}>
              <h1 id="home-title">
                <span><span>Find the cracks</span></span>{" "}
                <span><span>in your AWS.</span></span>
              </h1>
              <p className={styles.heroLead} data-home-enter>
                A read-only AWS scanner that shows where your account needs attention, which resources are affected, and how to fix them.
              </p>
              <div className={styles.heroActions} data-home-enter>
                <Link href="/demo" className={styles.button}>Open the demo <ArrowUpRight size={18} aria-hidden="true" /></Link>
                <a href="#checks" className={styles.textLink}>Browse checks <ArrowDown size={16} aria-hidden="true" /></a>
              </div>
            </div>
            <HomeReport score={postureScore(findings)} pillars={pillars} />
          </div>
          <div className={`${styles.shell} ${styles.heroFacts}`} data-home-enter>
            <span>AWS Well-Architected Framework</span>
            <span>Six pillars · Read-only access</span>
          </div>
        </section>
        <section id="demo" className={styles.demo} aria-labelledby="home-demo-title">
          <div className={styles.shell}>
            <div className={styles.demoIntro}>
              <h2 id="home-demo-title" className={styles.title} data-home-enter>Explore a scan</h2>
              <p className={styles.lead} data-home-enter>Compare sample scans, filter findings by severity, and open any result to see the affected resource and the suggested fix.</p>
            </div>
            <div className={styles.demoFrame} data-home-enter><Dashboard scans={scans} caption="Scan explorer" embedded /></div>
          </div>
        </section>
        <HomeWorkflow />
        <HomeChecks />
        <HomeStatus />
      </main>
      <HomeFooter />
      <HomeMotion />
    </div>
  );
}
