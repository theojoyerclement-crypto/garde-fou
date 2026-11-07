import { createClient } from 'npm:@supabase/supabase-js@2';
import OpenAI from 'npm:openai';

Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!, {
    global: { headers: { Authorization: req.headers.get('Authorization')! } },
  });
  const { data } = await supabase.auth.getUser();
  if (!data.user) return new Response('Unauthorized', { status: 401 });
  const openai = new OpenAI();
  const { question } = await req.json();
  const r = await openai.responses.create({ model: 'gpt-4o-mini', input: question });
  return Response.json({ answer: r.output_text });
});
