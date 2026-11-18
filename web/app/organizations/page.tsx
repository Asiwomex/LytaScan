import { redirect } from "next/navigation";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { OrganizationWorkspace } from "@/components/account/organization-workspace";

export const metadata = { title: "Organizations | LytaScan", robots: { index: false } };

export default function OrganizationsPage() {
  if (!ACCOUNTS_ONLINE && !LOCAL_ONBOARDING) redirect("/sign-in");
  return <OrganizationWorkspace />;
}
