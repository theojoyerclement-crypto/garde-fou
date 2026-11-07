import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const { userId } = await req.json();
  const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  await admin.from('profiles').delete().eq('id', userId);
  return new Response('ok');
});
