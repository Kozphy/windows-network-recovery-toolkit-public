/**
 * @file Supabase browser singleton for the Next.js SaaS demo frontend.
 */
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";

/**
 * Shared Supabase browser client configured from Next.js public env vars.
 *
 * @remarks
 * Network: Uses anon key against `NEXT_PUBLIC_SUPABASE_URL`; all authorization
 * for backend API routes still flows through Bearer tokens handled in pages.
 *
 * Constraints: URLs/keys missing at build time yield an empty-configuration
 * client; callers must handle failed sign-in/session states.
 */
export const supabase = createClient(supabaseUrl, supabaseAnonKey);
