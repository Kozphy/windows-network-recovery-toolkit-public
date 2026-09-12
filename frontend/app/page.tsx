/**
 * @file Next.js App Router home route (`/`).
 *
 * Responsibility: Render the portfolio marketing hero (`NetworkToolkitHero`) and static links into optional
 * demo surfaces (`/login`, `/dashboard`, `/billing`, `/platform`). Does not invoke toolkit Python CLIs or
 * collect telemetry.
 *
 * System placement: `frontend/app/page.tsx`; backend APIs live under `backend/` and are reachable only via
 * explicit client code or env-configured URLs.
 *
 * @remarks Audit / safety boundaries: This page is informational UI only. Routes such as `/login` may depend
 *   on Supabase env at build/prerender time—configure env vars documented in frontend README before CI build.
 */

import Link from "next/link";
import NetworkToolkitHero from "../components/NetworkToolkitHero";

/** Default landing composition: toolkit hero followed by outbound navigation list. Pure presentational JSX. */
export default function HomePage() {
  return (
    <main className="min-h-screen bg-slate-100/85 px-3 py-8 sm:px-5">
      <div className="mx-auto max-w-[1200px]">
        {/* Portfolio hero */}
        <NetworkToolkitHero />

        <div className="mt-12 rounded-3xl border border-slate-200/80 bg-white/90 px-6 py-8 shadow-lg shadow-slate-200/50 backdrop-blur-sm">
          <h2 className="text-xl font-semibold tracking-tight text-slate-800">Toolkit routes</h2>
          <p className="mt-2 text-sm leading-relaxed text-slate-600">
            {`Client Agent → API → Diagnosis Engine → Dashboard → Billing (optional SaaS demos).`}
          </p>
          <ul className="mt-6 space-y-2 text-sm font-medium text-blue-700">
            <li>
              <Link className="hover:underline" href="/login">
                /login
              </Link>
            </li>
            <li>
              <Link className="hover:underline" href="/dashboard">
                /dashboard
              </Link>
            </li>
            <li>
              <Link className="hover:underline" href="/billing">
                /billing
              </Link>
            </li>
            <li>
              <Link className="hover:underline" href="/platform">
                /platform
              </Link>{" "}
              <span className="text-xs font-normal text-slate-500">
                metrics — set <code className="rounded bg-slate-100 px-1">NEXT_PUBLIC_PLATFORM_API</code>
              </span>
            </li>
          </ul>
        </div>
      </div>
    </main>
  );
}
