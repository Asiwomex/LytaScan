import type { Metadata } from "next";

import { AccountApp } from "@/components/account/account-app";
import { Footer } from "@/components/site/sections";
import { SiteHeader } from "@/components/site/site-header";
import { ACCOUNTS_ONLINE } from "@/lib/backend";
import { SessionScan } from "@/components/session-scan/session-scan";

export const metadata: Metadata = {
  title: "Your AWS accounts · LytaScan",
  description: "Sign in to connect an AWS account and scan it.",
  // A page that is different for every signed-in person has no place in
  // search results.
  robots: { index: false },
};

export default function AccountPage() {
  if (!ACCOUNTS_ONLINE) return <SessionScan />;
  return (
    <>
      <SiteHeader />
      <main className="mx-auto min-h-[70vh] max-w-6xl px-4 py-[clamp(2.5rem,7vw,5rem)] sm:px-6">
        <AccountApp />
      </main>
      <Footer />
    </>
  );
}
