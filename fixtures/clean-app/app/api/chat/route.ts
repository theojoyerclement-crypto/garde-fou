// Secure route: Garde-Fou must report nothing here.
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { auth } from '@/auth';

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { messages } = await req.json();
  return streamText({ model: openai('gpt-4o-mini'), messages }).toTextStreamResponse();
}
