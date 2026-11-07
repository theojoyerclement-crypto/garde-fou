import OpenAI from 'openai';
import type { NextApiRequest, NextApiResponse } from 'next';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../lib/auth-options';

const openai = new OpenAI();

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).end();
  const r = await openai.responses.create({ model: 'gpt-4o-mini', input: String(req.body.text).slice(0, 4000) });
  res.json({ summary: r.output_text });
}
