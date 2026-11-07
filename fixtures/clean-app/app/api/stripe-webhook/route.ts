// Webhooks are public by design (Stripe signs the payload).
import Stripe from 'stripe';
import { createClient } from '@supabase/supabase-js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(
    await req.text(),
    req.headers.get('stripe-signature')!,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );
  if (event.type === 'checkout.session.completed') {
    await admin.from('orders').update({ paid: true }).eq('id', event.data.object.id);
  }
  return new Response('ok');
}
