import type { Metadata } from "next";

import { DemoWorkspace } from "@/components/demo-workspace";
import { loadDemoScan } from "@/lib/scans";

export const metadata: Metadata = {
  title: "AWS posture demo | LytaScan",
  description: "Explore posture scores, scan history, and findings from a fictional AWS account.",
};

export default function DemoPage() {
  return <DemoWorkspace scan={loadDemoScan()} />;
}
