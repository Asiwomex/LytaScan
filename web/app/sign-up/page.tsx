import { OnboardingAuth } from "@/components/account/onboarding-auth";

export const metadata = { title: "Create your account | LytaScan", robots: { index: false } };

export default function SignUpPage() {
  return <main className="px-4 py-14"><OnboardingAuth mode="sign-up" /></main>;
}
