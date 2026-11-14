import { ONBOARDING_API } from "./backend";

export type Organization = { organization_id: string; name: string; role: string };
export const REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-west-2"] as const;
export type Connection = {
  account_connection_id: string;
  aws_account_id: string;
  name: string;
  region: (typeof REGIONS)[number];
  role_arn: string;
  status: "pending" | "verified" | "failed";
  verified_at: string | null;
};
export type ConnectionSetup = Connection & { launch_url: string | null };

export class OnboardingError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export async function onboardingRequest<T>(
  path: string, body?: unknown, token?: string, method = body === undefined ? "GET" : "POST",
): Promise<T> {
  const response = await fetch(`${ONBOARDING_API}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new OnboardingError(
      typeof payload?.detail === "string" ? payload.detail : "Check your entries and try again.",
      response.status,
    );
  }
  return payload as T;
}
