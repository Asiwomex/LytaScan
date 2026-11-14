"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Menu, X } from "lucide-react";

import { Mark } from "@/components/site/mark";
import { useSignedIn } from "@/lib/auth";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { REPO_URL } from "@/lib/links";
import styles from "./home.module.css";

const sections = [
  { id: "demo", label: "Demo" },
  { id: "how-it-works", label: "How it works" },
  { id: "checks", label: "Checks" },
  { id: "status", label: "Status" },
];

export function HomeHeader() {
  const [open, setOpen] = useState(false);
  const signedIn = useSignedIn();
  const accountAvailable = ACCOUNTS_ONLINE || LOCAL_ONBOARDING;
  const accountHref = signedIn ? "/organizations" : "/sign-in";
  const accountLabel = signedIn ? "Organizations" : "Sign in";

  return (
    <header className={styles.header}>
      <a className={styles.skip} href="#home-main">Skip to content</a>
      <div className={`${styles.shell} ${styles.headerInner}`}>
        <Link href="/" className={styles.brand} onClick={() => setOpen(false)}>
          <Mark className={styles.logo} sound="var(--home-accent)" />
          LytaScan
        </Link>
        <nav aria-label="Homepage" className={styles.desktopNav}>
          {sections.map(({ id, label }) => <a key={id} href={`#${id}`}>{label}</a>)}
        </nav>
        <div className={styles.headerActions}>
          <a className={styles.sourceLink} href={REPO_URL}>Source <ArrowUpRight size={15} aria-hidden="true" /></a>
          {accountAvailable && <Link className={styles.accountLink} href={accountHref}>{accountLabel}</Link>}
        </div>
        <button className={styles.menuButton} type="button" aria-expanded={open} aria-controls="home-mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"} onClick={() => setOpen(!open)}>
          {open ? <X size={22} aria-hidden="true" /> : <Menu size={22} aria-hidden="true" />}
        </button>
      </div>
      <nav id="home-mobile-nav" aria-label="Mobile homepage" hidden={!open} className={`${styles.shell} ${styles.mobileNav}`}>
        {sections.map(({ id, label }) => <a key={id} href={`#${id}`} onClick={() => setOpen(false)}>{label}</a>)}
        <a href={REPO_URL}>Source <ArrowUpRight size={15} aria-hidden="true" /></a>
        {accountAvailable && <Link href={accountHref}>{accountLabel}</Link>}
      </nav>
    </header>
  );
}
