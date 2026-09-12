import "./globals.css";
import type { ReactNode } from "react";

/**
 * Root layout for the optional Next.js dashboard shipped beside `backend/` demo routes.
 *
 * Purpose: Provide the HTML shell and global styles for SaaS-oriented pages (billing, metrics) that
 * talk to local FastAPI instances only when operators start them explicitly.
 *
 * Side effects: None at build time beyond bundling CSS; runtime fetches depend on child routes.
 *
 * Constraints: This UI is not required for `python -m src` or `failure_system` workflows.
 */
export const metadata = {
  title: "WNRT SaaS Dashboard",
  description: "Windows Network Recovery Toolkit SaaS frontend",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
