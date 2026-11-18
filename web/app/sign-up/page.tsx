import { redirect } from "next/navigation";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { OnboardingAuth } from "@/components/account/onboarding-auth";

export const metadata = { title: "Create your account | LytaScan", robots: { index: false } };

export default function SignUpPage() {
  if (!ACCOUNTS_ONLINE && !LOCAL_ONBOARDING) redirect("/sign-in");
  return <main className="px-4 py-14"><OnboardingAuth mode="sign-up" /></main>;
}
