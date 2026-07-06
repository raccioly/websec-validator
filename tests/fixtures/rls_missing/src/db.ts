import { createClient } from "@supabase/supabase-js";

// Env-based (no literal key committed) → intended_public_supabase stays empty → MEDIUM/LOW, not HIGH.
export const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
);
