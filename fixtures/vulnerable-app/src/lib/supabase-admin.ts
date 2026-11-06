import { createClient } from '@supabase/supabase-js';

// VULNERABLE: the service_role key bypasses Row Level Security, and the
// NEXT_PUBLIC_ prefix ships it to every visitor's browser.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);
