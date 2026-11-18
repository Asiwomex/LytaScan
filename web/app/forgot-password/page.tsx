import { redirect } from "next/navigation";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING } from "@/lib/backend";
import { OnboardingAuth } from "@/components/account/onboarding-auth";

export const metadata = { title: "Reset your password | LytaScan", robots: { index: false } };

export default function ForgotPasswordPage() {
  if (!ACCOUNTS_ONLINE && !LOCAL_ONBOARDING) redirect("/sign-in");
  return <main className="px-4 py-14"><OnboardingAuth mode="forgot-password" /></main>;
}
