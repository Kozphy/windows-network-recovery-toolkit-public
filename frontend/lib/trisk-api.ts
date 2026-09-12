/**
 * Client helpers for the `/v1` technology-risk (Trisk) API.
 *
 * @remarks
 * Local demo stack: defaults to `http://localhost:8000` and a dev token with
 * read-only `auditor_readonly` role. These helpers do not expose write endpoints.
 */

/** Backend origin for Trisk routes; trailing slashes stripped from `NEXT_PUBLIC_API_BASE`. */
export const TRISK_API_BASE =
  typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_BASE
    ? process.env.NEXT_PUBLIC_API_BASE.replace(/\/$/, "")
    : "http://localhost:8000";

/** `localStorage` key for the demo API token (`X-Api-Token` header). */
export const TRISK_TOKEN_KEY = "TRISK_API_TOKEN";

/** `localStorage` key for the demo API role (`X-Api-Role` header). */
export const TRISK_ROLE_KEY = "TRISK_API_ROLE";

/**
 * Build read-only demo auth headers for Trisk requests.
 *
 * @returns Headers with `X-Api-Token` and `X-Api-Role` (default `auditor_readonly`).
 * On the server, falls back to `NEXT_PUBLIC_TRISK_TOKEN` or `dev-trisk-token`.
 *
 * @remarks
 * Browser calls read from `localStorage`; this is a local demo pattern, not production SSO.
 */
export function triskHeaders(): HeadersInit {
  if (typeof window === "undefined") {
    return {
      "X-Api-Token": process.env.NEXT_PUBLIC_TRISK_TOKEN || "dev-trisk-token",
      "X-Api-Role": "auditor_readonly",
    };
  }
  return {
    "X-Api-Token": localStorage.getItem(TRISK_TOKEN_KEY) || "dev-trisk-token",
    "X-Api-Role": localStorage.getItem(TRISK_ROLE_KEY) || "auditor_readonly",
    "Content-Type": "application/json",
  };
}

/**
 * Perform a read-only JSON GET/POST against the Trisk API.
 *
 * @param path - Relative path such as `/v1/incidents` or `/v1/reports/executive`.
 * @param options - Standard fetch options; `triskHeaders()` are merged in.
 * @returns Parsed JSON response body.
 * @throws {Error} When the API responds with a non-2xx status code.
 *
 * @remarks
 * Uses {@link TRISK_API_BASE} and {@link triskHeaders} for demo token auth.
 */
export async function triskFetch(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers || {});
  const base = triskHeaders();
  Object.entries(base).forEach(([k, v]) => headers.set(k, String(v)));
  const resp = await fetch(`${TRISK_API_BASE}${path}`, { ...options, headers });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Trisk API ${resp.status}: ${text}`);
  }
  return resp.json();
}
