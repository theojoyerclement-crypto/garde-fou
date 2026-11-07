import { createClient } from '@supabase/supabase-js';

// TODO: check the caller is an admin
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export const DELETE = async (req: Request) => {
  const { userId } = await req.json();
  await admin.auth.admin.deleteUser(userId);
  return new Response(null, { status: 204 });
};
