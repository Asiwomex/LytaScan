import { OrganizationWorkspace } from "@/components/account/organization-workspace";

export const metadata = { title: "Connect an AWS account | LytaScan", robots: { index: false } };

import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { SessionScan } from "@/components/session-scan/session-scan";

export default function ConnectPage() {
  if (!ACCOUNTS_ONLINE && !LOCAL_ONBOARDING) return <SessionScan />;
  return <OrganizationWorkspace connecting />;
}
