import { OnboardingAuth } from "@/components/account/onboarding-auth";

export const metadata = { title: "Sign in | LytaScan", robots: { index: false } };

export default function SignInPage() {
  return <main className="px-4 py-14"><OnboardingAuth mode="sign-in" /></main>;
}
