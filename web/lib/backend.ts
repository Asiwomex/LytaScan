// Public build-time settings for the hosted API and Cognito identity service.
// Local onboarding is available only in development builds.
// Missing hosted settings disable account actions. The sign-in route stays discoverable.

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "";
export const COGNITO_DOMAIN = process.env.NEXT_PUBLIC_COGNITO_DOMAIN ?? "";
export const COGNITO_CLIENT_ID = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID ?? "";
export const LOCAL_ONBOARDING =
  process.env.NODE_ENV === "development" && process.env.NEXT_PUBLIC_LOCAL_ONBOARDING === "true";
export const REGISTRATION_ENABLED =
  LOCAL_ONBOARDING || process.env.NEXT_PUBLIC_ENABLE_REGISTRATION === "true";
export const ONBOARDING_API = LOCAL_ONBOARDING ? "http://127.0.0.1:8000" : API_URL;

/** A hosted API URL is configured for this build. */
export const API_ONLINE = API_URL !== "";

/** All hosted account settings are present. Availability requires runtime verification. */
export const ACCOUNTS_ONLINE = API_ONLINE && COGNITO_DOMAIN !== "" && COGNITO_CLIENT_ID !== "";
