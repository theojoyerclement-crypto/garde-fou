import { prisma } from '@/lib/prisma';

export async function GET(req: Request) {
  if (req.headers.get('x-cron-key') !== process.env.CRON_SECRET) {
    return new Response('Forbidden', { status: 403 });
  }
  await prisma.session.deleteMany({ where: { expires: { lt: new Date() } } });
  return new Response('ok');
}
