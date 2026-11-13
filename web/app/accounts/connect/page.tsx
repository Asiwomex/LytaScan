import { OrganizationWorkspace } from "@/components/account/organization-workspace";

export const metadata = { title: "Connect an AWS account | Pillarscan", robots: { index: false } };

export default function ConnectPage() {
  return <OrganizationWorkspace connecting />;
}
