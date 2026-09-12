"use client";

/**
 * @file Shared layout shell for optional Next.js platform demo pages (`frontend/app/platform/*`).
 *
 * @remarks
 * Read-only UI over local FastAPI `/platform/*` routes when `NEXT_PUBLIC_PLATFORM_API` is set.
 * Not required to run the Python CLI or technology risk API (`/incidents`, `/risks`, etc.).
 *
 * **Audit notes:** Demo RBAC role is stored in `localStorage` only — not production auth.
 */

import Link from "next/link";
import { ReactNode } from "react";

export const PLATFORM_API_BASE =
  typeof process !== "undefined" && process.env.NEXT_PUBLIC_PLATFORM_API
    ? process.env.NEXT_PUBLIC_PLATFORM_API.replace(/\/$/, "")
    : "";

export const DEMO_ROLE_KEY = "PLATFORM_DEMO_RBAC_ROLE";

const NAV = [
  { href: "/platform", label: "Overview" },
  { href: "/platform/incidents", label: "Incidents" },
  { href: "/platform/proxy-events", label: "Proxy incidents" },
  { href: "/platform/causation", label: "Causation" },
  { href: "/platform/policy", label: "Policy" },
  { href: "/platform/evidence", label: "Evidence" },
  { href: "/platform/policies", label: "Policies" },
  { href: "/platform/replay", label: "Replay" },
  { href: "/platform/slo", label: "SLO" },
  { href: "/platform/timeline", label: "Timeline" },
  { href: "/platform/sre", label: "SRE Incidents" },
  { href: "/platform/risk-overview", label: "Risk (/v1)" },
  { href: "/platform/evidence-timeline", label: "Event timeline" },
  { href: "/platform/audit-viewer", label: "Audit viewer" },
] as const;

export function PlatformShell(props: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  active?: string;
}) {
  return (
    <main style={{ padding: "1.25rem", maxWidth: 1100, margin: "0 auto", fontFamily: "system-ui" }}>
      <header style={{ marginBottom: "1.25rem" }}>
        <h1 style={{ marginTop: 0, marginBottom: 4 }}>{props.title}</h1>
        {props.subtitle ? (
          <p style={{ margin: 0, opacity: 0.8, fontSize: "0.95rem" }}>{props.subtitle}</p>
        ) : null}
        <p style={{ fontSize: "0.82rem", opacity: 0.75, marginTop: 8 }}>
          Observation ≠ Proof · Correlation ≠ Causation · Confidence ≠ Certainty
        </p>
      </header>
      <nav
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 8,
          marginBottom: "1.25rem",
          paddingBottom: 12,
          borderBottom: "1px solid #ddd",
        }}
      >
        {NAV.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            style={{
              padding: "6px 10px",
              borderRadius: 6,
              textDecoration: "none",
              background: props.active === item.href ? "#1e3a5f" : "#f1f5f9",
              color: props.active === item.href ? "#fff" : "#0f172a",
              fontSize: "0.88rem",
            }}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      {!PLATFORM_API_BASE ? (
        <p style={{ color: "salmon" }}>Set NEXT_PUBLIC_PLATFORM_API (see frontend/.env.local.example)</p>
      ) : null}
      {props.children}
    </main>
  );
}

export async function platformFetch(
  path: string,
  init?: RequestInit & { role?: string },
): Promise<Response> {
  if (!PLATFORM_API_BASE) throw new Error("NEXT_PUBLIC_PLATFORM_API not set");
  const role =
    init?.role ||
    (typeof window !== "undefined" ? window.localStorage.getItem(DEMO_ROLE_KEY) : null) ||
    "admin";
  const headers: Record<string, string> = {
    "X-Operator-Role": role,
    "X-Operator-Id": "nextjs-platform-ui",
    ...(init?.headers as Record<string, string> | undefined),
  };
  return fetch(`${PLATFORM_API_BASE}${path}`, { ...init, headers });
}
