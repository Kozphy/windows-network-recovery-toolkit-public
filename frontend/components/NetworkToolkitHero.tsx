/**
 * @file Single-file hero presentation for the optional Next.js marketing surface.
 *
 * Responsibility: Visual summary of **local-first** Windows network diagnostics vocabulary (detect → attribute →
 * decide → rollback → audit). Communicates tooling categories (``.bat``, JSONL, `python -m src`) without
 * executing probes or issuing HTTP requests itself.
 *
 * System placement: Consumed only from `frontend/app/page.tsx` in the demo bundle; orthogonal to batch scripts
 * under `scripts/`.
 *
 * @remarks Rendering uses Tailwind utilities and inline SVG gradients only—no raster images, no analytics hooks.
 *
 * Accessibility: Outer section exposes `aria-label`; decorative SVG/graphic nodes set `aria-hidden` where duplicated
 * cues exist in headings.
 *
 * @see root `README.md` for authoritative CLI and safety boundaries mirrored in marketing copy tone.
 */
import type { ReactNode } from "react";

/* -------------------------------------------------------------------------- */
/* Logo: isometric SVG cube (brand mark)                                       */
/* -------------------------------------------------------------------------- */
function BrandCubeIcon({ className = "h-16 w-16" }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 64 72"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <defs>
        <linearGradient id="heroFaceTop" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#0ea5e9" />
        </linearGradient>
        <linearGradient id="heroFaceLeft" x1="100%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#1d4ed8" />
          <stop offset="100%" stopColor="#2563eb" />
        </linearGradient>
        <linearGradient id="heroFaceRight" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#0284c7" />
          <stop offset="100%" stopColor="#0369a1" />
        </linearGradient>
      </defs>
      <path d="M32 4 L60 22 L60 42 L32 58 L4 42 L4 22 Z" fill="url(#heroFaceTop)" />
      <path d="M4 22 L32 4 L32 26 L4 42 Z" fill="url(#heroFaceLeft)" />
      <path d="M32 4 L60 22 L60 42 L32 26 Z" fill="url(#heroFaceRight)" />
      <path
        opacity="0.35"
        d="M32 26 L58 41 L58 39 L32 23 Z"
        fill="white"
      />
    </svg>
  );
}

/* -------------------------------------------------------------------------- */
/* Glowing teal decision cube — receives “signal” motif                        */
/* -------------------------------------------------------------------------- */
function DecisionCubeGraphic({ className = "w-44 h-48" }: { className?: string }) {
  return (
    <div className={`relative ${className}`}>
      <div
        className="animate-pulseGlow absolute inset-[-18%] rounded-[2rem] bg-gradient-to-br from-teal-400/90 via-cyan-400 to-emerald-400 blur-3xl"
        aria-hidden
      />
      <svg
        viewBox="0 0 120 130"
        className="relative z-10 h-full w-full drop-shadow-[0_12px_40px_rgba(20,184,166,0.45)]"
        xmlns="http://www.w3.org/2000/svg"
        aria-label="Decision engine"
      >
        <defs>
          <linearGradient id="cubeTealTop" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#5eead4" />
            <stop offset="100%" stopColor="#2dd4bf" />
          </linearGradient>
          <linearGradient id="cubeTealL" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#0d9488" />
            <stop offset="100%" stopColor="#14b8a6" />
          </linearGradient>
          <linearGradient id="cubeTealR" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0891b2" />
            <stop offset="100%" stopColor="#0e7490" />
          </linearGradient>
          <filter id="innerGlowDec" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="1.6" result="b" />
            <feComposite in="SourceGraphic" in2="b" operator="over" />
          </filter>
        </defs>
        <path
          d="M60 12 L112 42 L112 88 L60 116 L8 88 L8 42 Z"
          fill="url(#cubeTealTop)"
          filter="url(#innerGlowDec)"
        />
        <path d="M8 42 L60 12 L60 64 L8 88 Z" fill="url(#cubeTealL)" />
        <path d="M60 12 L112 42 L112 88 L60 64 Z" fill="url(#cubeTealR)" />
        <text
          x="60"
          y="74"
          textAnchor="middle"
          fill="#ffffff"
          className="font-mono text-[13px] font-bold tracking-[0.2em]"
        >
          DECIDE
        </text>
        <circle cx="60" cy="68" r="3" fill="white" opacity="0.95" />
      </svg>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Shared glass pill / card primitives                                         */
/* -------------------------------------------------------------------------- */
function GlassPill({
  label,
  sub,
  className,
}: {
  label: string;
  sub?: string;
  className?: string;
}) {
  return (
    <div
      className={`rounded-2xl border border-white/70 bg-white/55 px-4 py-2.5 shadow-lg shadow-slate-300/35 backdrop-blur-md ${className ?? ""}`}
    >
      <div className="text-[13px] font-semibold tracking-tight text-slate-800">{label}</div>
      {sub ? <div className="mt-1 font-mono text-[11px] text-slate-500">{sub}</div> : null}
    </div>
  );
}

function MetricChip({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-teal-300/45 bg-teal-50 px-2.5 py-0.5 font-mono text-[10px] font-medium leading-none text-teal-900 shadow-sm shadow-teal-200/60">
      {children}
    </span>
  );
}

function MiniJsonl({ line }: { line: string }) {
  return (
    <div className="truncate rounded-md border border-slate-200/80 bg-white/70 px-2 py-1 font-mono text-[10px] leading-snug text-slate-500 shadow-inner backdrop-blur-sm">
      {line}
    </div>
  );
}

function CodeGlyph({ symbol }: { symbol: string }) {
  return (
    <span
      aria-hidden
      className="select-none rounded border border-blue-100 bg-gradient-to-br from-blue-50 to-cyan-50 px-2 py-0.5 font-mono text-xs font-semibold text-blue-700 shadow-sm shadow-blue-200/70"
    >
      {symbol}
    </span>
  );
}

/**
 * Portfolio hero banner: brand cube, headline, pipeline strip, illustrative endpoint/tiles.
 *
 * Pure function component — no hooks, props, network, or persistence.
 *
 * @returns JSX section sized for responsive `lg` breakpoints.
 */
export default function NetworkToolkitHero() {
  return (
    <section
      className="relative isolate mx-auto w-full max-w-[1200px] min-h-[500px] overflow-hidden rounded-3xl border border-slate-200/70 bg-white shadow-2xl shadow-slate-300/35 ring-1 ring-slate-100"
      aria-label="Windows Network Recovery Toolkit — hero banner"
    >
      {/* ── Atmospheric layers: soft gradient blobs + dotted technical grid ── */}
      <div
        aria-hidden
        className="pointer-events-none absolute -left-[12%] top-[-20%] h-[520px] w-[520px] rounded-full bg-gradient-to-br from-cyan-300/35 via-transparent to-transparent blur-3xl"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -bottom-[18%] -right-[8%] h-[460px] w-[460px] rounded-full bg-gradient-to-tl from-blue-400/20 via-teal-200/25 to-transparent blur-3xl"
      />
      <div
        aria-hidden
        className="absolute inset-0 bg-[radial-gradient(circle_at_center,#cbd5e1_1px,transparent_1px)] [background-size:22px_22px] opacity-[0.42]"
      />

      <div className="relative z-10 grid grid-cols-1 gap-y-14 px-5 py-10 sm:px-9 lg:grid-cols-12 lg:gap-x-10 lg:px-11 lg:py-14">
        {/* ── LEFT: brand, headline, narrative, pipeline strip ──────────── */}
        <div className="flex flex-col justify-center lg:col-span-5">
          <div className="mb-8 flex items-center gap-5">
            <div className="rounded-3xl bg-gradient-to-br from-white via-sky-50/80 to-cyan-50/90 p-4 shadow-xl shadow-blue-400/25 ring-1 ring-blue-100/80">
              <BrandCubeIcon className="h-16 w-16 sm:h-[4.75rem] sm:w-[4.75rem]" />
            </div>
            <div>
              <h1 className="text-[1.62rem] font-bold leading-snug tracking-tight text-slate-900 sm:text-[1.75rem] xl:text-[1.92rem]">
                Windows Network
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-cyan-600 to-teal-600 bg-clip-text text-transparent">
                  Recovery Toolkit
                </span>
              </h1>
              <p className="mt-2 max-w-sm text-[15px] font-medium tracking-wide text-blue-950/85 sm:text-base">
                Agentic Endpoint Reliability for Windows Diagnostics
              </p>
            </div>
          </div>

          <p className="max-w-md text-[15px] leading-relaxed text-slate-600 sm:text-[0.9675rem]">
            Detect proxy drift, attribute suspicious changes, preview remediation, rollback safely, and
            audit every decision locally.
          </p>

          {/* Pipeline */}
          <div className="mt-8 rounded-2xl border border-teal-200/55 bg-teal-50/40 px-4 py-3.5 backdrop-blur-md shadow-inner shadow-teal-200/35">
            <div className="mb-2 flex flex-wrap items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-teal-800/85">
              <CodeGlyph symbol="{ }" />
              <span className="text-teal-700/90">&lt;/&gt;</span>
              <span>Local-first pipeline</span>
            </div>
            <div className="flex flex-wrap items-center gap-x-1.5 gap-y-2 text-[12.5px] font-semibold text-slate-700">
              <span className="whitespace-nowrap text-teal-700">Detect</span>
              <Arrow />
              <span className="whitespace-nowrap text-slate-800">Attribute</span>
              <Arrow />
              <span className="whitespace-nowrap text-slate-800">Decide</span>
              <Arrow />
              <span className="whitespace-nowrap text-teal-800">Rollback</span>
              <Arrow />
              <span className="whitespace-nowrap text-blue-900">Audit</span>
            </div>
          </div>

          <div className="mt-7 flex flex-wrap gap-3">
            <MetricChip>{`heartbeat_total +12`}</MetricChip>
            <MetricChip>{`proxy_drift ⚠ low`}</MetricChip>
            <MetricChip>{`preview_only`}</MetricChip>
          </div>
        </div>

        {/* ── RIGHT: floating signals → decision cube → endpoint tiles ─────── */}
        <div className="relative min-h-[420px] lg:col-span-7">
          {/* Scattered drifting signal pills (simulate raw telemetry ingestion) */}
          {/* Large viewports only — absolute choreography */}
          <div className="absolute inset-0 hidden lg:block">
            <GlassPill
              label="DNS"
              sub="nslookup · forwarders stable"
              className="animate-floatSoft absolute left-0 top-[2%] w-[154px]"
            />
            <GlassPill
              label="Proxy"
              sub="HKCU / WinINET diff"
              className="animate-floatSlow absolute left-[6%] top-[54%] w-[154px] [animation-delay:450ms]"
            />
            <GlassPill
              label="TCP :443"
              sub="HTTPS handshake probes"
              className="animate-floatSoft absolute left-[18%] top-[28%] w-[154px] [animation-delay:820ms]"
            />
            <GlassPill
              label="Git / npm"
              sub="repo & registry proxy stacks"
              className="animate-drift absolute right-[42%] top-[6%] w-[166px] [animation-delay:210ms]"
            />
            <GlassPill
              label="pip"
              sub="wheel index timeouts"
              className="animate-floatSlow absolute right-[10%] top-[62%] w-[146px] [animation-delay:550ms]"
            />
            <GlassPill
              label="WinHTTP"
              sub="netsh parity check"
              className="animate-floatSoft absolute bottom-[14%] left-[26%] w-[158px] [animation-delay:970ms]"
            />
          </div>

          {/* Narrow viewports — wrap signal chips safely */}
          <div
            className="relative z-10 flex flex-wrap justify-center gap-2 lg:hidden"
            aria-label="Telemetry signals condensed"
          >
            <GlassPill label="DNS" sub="resolver" className="w-[calc(50%-6px)] sm:w-auto" />
            <GlassPill label="Proxy" sub="HKCU" className="w-[calc(50%-6px)] sm:w-auto" />
            <GlassPill label="TCP :443" className="w-[calc(50%-6px)] sm:w-auto" />
            <GlassPill label="WinINET" sub="PAC" className="w-[calc(50%-6px)] sm:w-auto" />
            <GlassPill label="Git" className="w-[calc(33%-6px)] sm:w-auto" />
            <GlassPill label="npm" className="w-[calc(33%-6px)] sm:w-auto" />
            <GlassPill label="pip" className="w-[calc(34%-6px)] sm:w-auto" />
          </div>

          {/* Center: glowing decision fusion */}
          <div className="relative z-10 mx-auto mt-10 flex justify-center lg:absolute lg:left-[46%] lg:top-[22%] lg:mt-0 lg:-translate-x-1/2 xl:left-[44%]">
            <DecisionCubeGraphic className="h-48 w-[11rem]" />
            {/* Curved motif: signals → cube (desktop) */}
            <svg
              className="pointer-events-none absolute -left-[88px] top-[54%] hidden h-24 w-28 opacity-45 lg:block"
              viewBox="0 0 100 72"
              aria-hidden
            >
              <defs>
                <linearGradient id="flowLineTeal" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#38bdf800" />
                  <stop offset="50%" stopColor="#2dd4bf" />
                  <stop offset="100%" stopColor="#14b8a6aa" />
                </linearGradient>
              </defs>
              <path
                d="M4 62 Q40 52 74 42"
                fill="none"
                stroke="url(#flowLineTeal)"
                strokeWidth="3"
                strokeLinecap="round"
                strokeDasharray="8 11"
              />
            </svg>
          </div>

          {/* Dashboard / endpoint cubes — organized column */}
          <div className="relative z-20 mx-auto mt-10 flex w-full max-w-[240px] flex-col gap-2.5 lg:absolute lg:right-6 lg:top-[8%] lg:mx-0 lg:mt-0 lg:max-w-[198px]">
            <GlassPanelHead title="Endpoints" eyebrow="Fleet view" accent="blue" />
            <EndpointMiniTile hostname="HASHED-EP • win11" chips={["Healthy", "LKG ✓"]} muted />
            <EndpointMiniTile hostname="HASHED-EP • corp" chips={["Drift proxy"]} muted={false} />
            <GlassPanelHead title="JSONL audit tail" eyebrow="append-only" accent="teal" />
            <MiniJsonl line={`{"schema_version":1,"kind":"heartbeat","endpoint":"…"} `} />
            <MiniJsonl line={`{"event_id":"evt-8fa3","risk":"rollback_preview","dry_run":true}`} />
            <div className="mt-1 flex flex-wrap gap-2">
              <MetricChip>KPI rollup</MetricChip>
              <MetricChip>RBAC: admin</MetricChip>
            </div>
          </div>

          {/* Bottom ribbon: code motifs + stray signal */}
          <div className="relative z-10 mt-10 flex max-w-[min(90%,560px)] flex-wrap items-center gap-3 px-2 lg:absolute lg:bottom-10 lg:left-[4%] lg:mt-0 lg:px-0">
            <CodeGlyph symbol="JSONL" />
            <CodeGlyph symbol=".bat" />
            <span className="font-mono text-[11px] text-slate-400">/</span>
            <CodeGlyph symbol="python -m src" />
          </div>
        </div>
      </div>
    </section>
  );
}

function Arrow() {
  return (
    <span aria-hidden className="mx-0.5 text-teal-500/95">
      →
    </span>
  );
}

function GlassPanelHead({
  title,
  eyebrow,
  accent,
}: {
  title: string;
  eyebrow: string;
  accent: "blue" | "teal";
}) {
  const bar =
    accent === "blue"
      ? "bg-gradient-to-r from-blue-500 to-sky-500"
      : "bg-gradient-to-r from-teal-500 to-cyan-500";
  return (
    <div
      className={`rounded-xl border border-white/60 bg-white/50 px-3 py-2 shadow-md backdrop-blur-md`}
    >
      <div className={`mb-2 h-[3px] w-14 rounded-full ${bar}`} />
      <div className="font-mono text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-500">
        {eyebrow}
      </div>
      <div className="font-semibold tracking-tight text-slate-800">{title}</div>
    </div>
  );
}

function EndpointMiniTile({
  hostname,
  chips,
  muted,
}: {
  hostname: string;
  chips: string[];
  muted: boolean;
}) {
  return (
    <div
      className={`rounded-xl border border-white/60 px-3 py-2 shadow-md backdrop-blur-md ${muted ? "bg-slate-50/70" : "bg-amber-50/75 ring-2 ring-amber-200/50"}`}
    >
      <div className="font-mono text-[11px] font-medium text-slate-700">{hostname}</div>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {chips.map((c) => (
          <span
            key={c}
            className={`rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${muted ? "bg-emerald-100 text-emerald-900" : "bg-amber-200/95 text-amber-950"}`}
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}
