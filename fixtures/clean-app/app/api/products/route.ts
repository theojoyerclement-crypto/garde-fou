// Public read with the anon key: RLS decides what is visible.
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export async function GET() {
  const { data } = await supabase.from('products').select('*');
  return Response.json(data);
}

export async function POST(req: Request) {
  const { email } = await req.json();
  await supabase.from('waitlist').insert({ email });
  return new Response(null, { status: 201 });
}
