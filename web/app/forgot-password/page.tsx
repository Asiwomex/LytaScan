import { OnboardingAuth } from "@/components/account/onboarding-auth";

export const metadata = { title: "Reset your password | Pillarscan", robots: { index: false } };

export default function ForgotPasswordPage() {
  return <main className="px-4 py-14"><OnboardingAuth mode="forgot-password" /></main>;
}
