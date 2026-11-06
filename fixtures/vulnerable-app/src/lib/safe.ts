// SAFE: nothing in this file must be reported (false-positive guard).
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';

// Server-only secret, no public prefix.
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Public by design.
export const publishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);

// Placeholders, not keys.
export const docs = 'Set OPENAI_API_KEY=sk-proj-... and STRIPE_SECRET_KEY=sk_live_... in .env';
