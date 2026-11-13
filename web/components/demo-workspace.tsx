"use client";

import Link from "next/link";
import { useState, useSyncExternalStore } from "react";
import { ArrowLeft, LayoutDashboard, ListFilter, RotateCcw } from "lucide-react";

import { Dashboard } from "@/components/dashboard";
import { Mark } from "@/components/site/mark";
import type { Scan } from "@/lib/scans";

const THEME_KEY = "pillarscan-demo-theme";
const THEME_CHANGED = "pillarscan-demo-theme-change";
const THEMES = ["system", "light", "dark"] as const;
type Theme = (typeof THEMES)[number];

function readTheme(): Theme {
  const value = localStorage.getItem(THEME_KEY);
  return value === "dark" || value === "light" ? value : "system";
}

function subscribeToTheme(listener: () => void) {
  window.addEventListener("storage", listener);
  window.addEventListener(THEME_CHANGED, listener);
  return () => {
    window.removeEventListener("storage", listener);
    window.removeEventListener(THEME_CHANGED, listener);
  };
}

export function DemoWorkspace({ scan }: { scan: Scan }) {
  const theme = useSyncExternalStore(subscribeToTheme, readTheme, () => "system" as const);
  const [resetCount, setResetCount] = useState(0);

  return (
    <div data-demo-theme={theme} className="min-h-screen bg-page text-sm text-ink lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
      <a href="#demo-content" className="sr-only z-50 rounded-md bg-surface p-3 focus:not-sr-only focus:fixed focus:top-3 focus:left-3">
        Skip to content
      </a>
      <aside className="border-b border-line bg-surface lg:sticky lg:top-0 lg:h-screen lg:border-r lg:border-b-0">
        <Link href="/" className="flex h-16 items-center gap-3 border-b border-line px-4 text-lg font-semibold tracking-tight lg:px-6">
          <Mark className="size-5" sound="var(--workspace-accent)" />
          Pillarscan
        </Link>
        <nav aria-label="Demo sections" className="flex flex-wrap gap-1 p-3 lg:flex-col lg:p-4">
          <a href="#demo-content" className="flex items-center gap-2.5 rounded-md px-3 py-2 font-medium hover:bg-page">
            <LayoutDashboard size={16} aria-hidden="true" /> Overview
          </a>
          <a href="#findings-heading" className="flex items-center gap-2.5 rounded-md px-3 py-2 font-medium hover:bg-page">
            <ListFilter size={16} aria-hidden="true" /> Findings
          </a>
          <Link href="/" className="flex items-center gap-2.5 rounded-md px-3 py-2 text-muted-ink hover:bg-page">
            <ArrowLeft size={16} aria-hidden="true" /> Back to site
          </Link>
        </nav>
      </aside>
      <div className="min-w-0">
        <header className="sticky top-0 z-20 flex min-h-16 flex-wrap items-center justify-between gap-3 border-b border-line bg-surface px-4 py-2 sm:px-8">
          <span className="rounded-md bg-page px-2.5 py-1 font-medium">Demo · Fictional AWS data</span>
          <label className="flex items-center gap-2 text-muted-ink">
            Theme
            <select
              className="rounded-md border border-line bg-surface px-2 py-1.5 text-ink"
              value={theme}
              onChange={(event) => {
                localStorage.setItem(THEME_KEY, event.target.value);
                window.dispatchEvent(new Event(THEME_CHANGED));
              }}
            >
              {THEMES.map((value) => (
                <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>
              ))}
            </select>
          </label>
        </header>
        <main id="demo-content" tabIndex={-1} className="mx-auto max-w-[1600px] scroll-mt-24 px-4 py-6 sm:px-8 sm:py-8">
          <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">AWS posture overview</h1>
              <p className="mt-1 text-muted-ink">Review the scan trend and open findings to see how to fix them.</p>
            </div>
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-md border border-line bg-surface px-3 py-2 font-medium hover:border-muted-ink"
              onClick={() => setResetCount((count) => count + 1)}
            >
              <RotateCcw size={15} aria-hidden="true" /> Reset demo
            </button>
          </div>
          <span className="sr-only" role="status">{resetCount > 0 ? "Demo filters and chart reset." : ""}</span>
          <Dashboard key={resetCount} scans={[scan]} caption="Sample scan" />
        </main>
      </div>
    </div>
  );
}
