import type { Metadata, Viewport } from "next";
import "./globals.css";

const TITLE = "Pillarscan: find the cracks in your AWS account";
const DESCRIPTION =
  "A read-only AWS posture review. Pillarscan scans an account and ranks every weak spot across security, reliability and cost, with the fix for each one.";

// Vercel sets this to the production domain at build time. Share images
// need an absolute URL, so local builds fall back to localhost.
const SITE_URL = process.env.VERCEL_PROJECT_PRODUCTION_URL
  ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
  : "http://localhost:3000";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: TITLE,
  description: DESCRIPTION,
  authors: [{ name: "Asiwome Boateng", url: "https://asiwomex.vercel.app/" }],
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    siteName: "Pillarscan",
    type: "website",
  },
  twitter: { card: "summary_large_image", title: TITLE, description: DESCRIPTION },
};

export const viewport: Viewport = {
  themeColor: "#0a1420",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" data-scroll-behavior="smooth" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
