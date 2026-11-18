import { SessionScan } from "@/components/session-scan/session-scan";

export const metadata = {
  title: "Scan your AWS account | LytaScan",
  description: "Connect temporary read-only AWS access, run a posture scan, and download your report.",
  robots: { index: false },
};

export default function SignInPage() {
  return <SessionScan />;
}
