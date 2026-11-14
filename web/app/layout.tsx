import type { Metadata, Viewport } from "next";
import "./globals.css";

const TITLE = "LytaScan | Read-only AWS posture scanner";
const DESCRIPTION =
  "Find configuration issues across the six AWS Well-Architected pillars. Inspect affected resources and see how to fix them with a read-only posture scan.";

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
    siteName: "LytaScan",
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
