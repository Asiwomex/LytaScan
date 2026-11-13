"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { rememberSession, signIn, type Session } from "@/lib/auth";
import { ACCOUNTS_ONLINE, LOCAL_ONBOARDING, REGISTRATION_ENABLED } from "@/lib/backend";
import { onboardingRequest } from "@/lib/onboarding";

export const FIELD = "mt-1 block min-h-10 w-full rounded-md border border-line bg-surface px-3 py-2 text-ink";
export const ACTION = "inline-flex min-h-10 items-center justify-center rounded-md bg-ink px-4 py-2 font-semibold text-surface disabled:opacity-50";
export const TEXT_LINK = "font-medium text-sound underline underline-offset-4";

type Mode = "sign-in" | "sign-up" | "forgot-password";

const TITLE = { "sign-in": "Sign in", "sign-up": "Create your account", "forgot-password": "Reset your password" };

export function OnboardingAuth({ mode }: { mode: Mode }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [issuedCode, setIssuedCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const registering = mode === "sign-up";
  const recovery = mode === "forgot-password";
  const enabled = (LOCAL_ONBOARDING || ACCOUNTS_ONLINE) && (!registering || REGISTRATION_ENABLED);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (!LOCAL_ONBOARDING) {
        await signIn(registering ? "signup" : recovery ? "forgotPassword" : "authorize", true);
      } else if (issuedCode) {
        await onboardingRequest("/local/confirm", { email, code });
        router.push("/sign-in");
      } else if (registering) {
        const result = await onboardingRequest<{ code: string }>("/local/register", { email, password });
        setIssuedCode(result.code);
        setPassword("");
      } else {
        rememberSession(await onboardingRequest<Session>("/local/sign-in", { email, password }));
        router.push("/organizations");
      }
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel mx-auto w-full max-w-lg p-6 text-ink sm:p-8">
      <h1 className="text-2xl font-semibold tracking-tight">{issuedCode ? "Verify your email" : TITLE[mode]}</h1>
      {LOCAL_ONBOARDING && (
        <p className="mt-3 rounded-md bg-page p-3 text-muted-ink">
          Local preview. Use an address ending in @example.test and a fictional password. Preview data resets when the local API restarts.
        </p>
      )}
      {!enabled ? (
        <p className="mt-4 text-muted-ink">
          {registering && ACCOUNTS_ONLINE ? "Registration is currently by invitation." : "The identity service is currently offline."}
        </p>
      ) : LOCAL_ONBOARDING && recovery ? (
        <p className="mt-4 text-muted-ink">The preview uses temporary fictional accounts. Email delivery and password reset run through Cognito in the hosted app.</p>
      ) : (
        <form onSubmit={submit} className="mt-5 grid gap-4">
          {LOCAL_ONBOARDING && (issuedCode ? (
            <label>
              Verification code
              <span className="block text-sm text-muted-ink">Preview code for {email} is <strong>{issuedCode}</strong>.</span>
              <input className={FIELD} autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" value={code} onChange={(event) => setCode(event.target.value)} required />
            </label>
          ) : (
            <>
              <label>
                Email
                <input className={FIELD} type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
              </label>
              <label>
                Password
                <input className={FIELD} type="password" autoComplete={registering ? "new-password" : "current-password"} minLength={12} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} required />
              </label>
            </>
          ))}
          {!LOCAL_ONBOARDING && <p className="text-muted-ink">Continue to Amazon Cognito to {recovery ? "request a password reset" : registering ? "register and verify your email" : "sign in securely"}.</p>}
          <button className={ACTION} disabled={busy}>
            {busy ? "Working…" : issuedCode ? "Verify email" : LOCAL_ONBOARDING ? TITLE[mode] : "Continue to Cognito"}
          </button>
        </form>
      )}
      {error && <p role="alert" className="mt-3 text-critical">{error}</p>}
      <nav aria-label="Account options" className="mt-6 flex flex-wrap gap-4 text-sm">
        {mode !== "sign-in" && <Link className={TEXT_LINK} href="/sign-in">Sign in</Link>}
        {mode === "sign-in" && REGISTRATION_ENABLED && <Link className={TEXT_LINK} href="/sign-up">Create an account</Link>}
        {mode === "sign-in" && ACCOUNTS_ONLINE && <Link className={TEXT_LINK} href="/forgot-password">Forgot password</Link>}
        <Link className={TEXT_LINK} href="/demo">Open demo</Link>
      </nav>
    </section>
  );
}
