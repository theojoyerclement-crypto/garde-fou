import { prisma } from '@/lib/prisma';

export async function POST(req: Request) {
  const { ownerId, text } = await req.json();
  const note = await prisma.note.create({ data: { ownerId, text } });
  return Response.json(note);
}
