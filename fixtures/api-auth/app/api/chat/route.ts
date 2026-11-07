// Deliberately insecure route used to test Garde-Fou. Do not deploy.
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({ model: 'gpt-4o', messages, max_tokens: 4000 });
  return Response.json(completion.choices[0]?.message);
}
