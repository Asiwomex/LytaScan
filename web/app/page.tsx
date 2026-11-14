import Link from "next/link";
import { ArrowDown, ArrowUpRight } from "lucide-react";

import { Dashboard } from "@/components/dashboard";
import { HomeHeader } from "@/components/site/home-header";
import { HomeMotion } from "@/components/site/home-motion";
import { HomeReport } from "@/components/site/home-report";
import { HomeChecks, HomeFooter, HomeStatus, HomeWorkflow } from "@/components/site/home-sections";
import heroStyles from "@/components/site/home-hero.module.css";
import styles from "@/components/site/home.module.css";
import { loadScans } from "@/lib/scans";

export default function Home() {
  const scans = loadScans();
  const demoScan = scans[0].report;

  return (
    <div id="top" className={styles.home}>
      <HomeHeader />
      <main id="home-main" tabIndex={-1}>
        <section className={heroStyles.hero} aria-labelledby="home-title">
          <div className={styles.shell}>
            <div className={heroStyles.intro}>
              <h1 id="home-title"><span>From AWS inventory</span>{" "}<span>to verified findings.</span></h1>
              <div>
                <p>Review AWS posture with read-only access. Trace failed checks to the affected resources and see how to verify a fix.</p>
                <div className={heroStyles.actions}>
                  <Link href="/demo" className={heroStyles.primary}>Open the demo <ArrowUpRight size={17} aria-hidden="true" /></Link>
                  <a href="#sample-review-console" className={heroStyles.secondary}>Explore the workflow <ArrowDown size={15} aria-hidden="true" /></a>
                </div>
              </div>
            </div>
            <HomeReport findings={demoScan.findings} rules={demoScan.scan.checks_run.length} regions={demoScan.scan.regions.length} />
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
