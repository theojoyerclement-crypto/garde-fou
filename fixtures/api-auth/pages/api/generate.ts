import Anthropic from '@anthropic-ai/sdk';
import type { NextApiRequest, NextApiResponse } from 'next';

const anthropic = new Anthropic();

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const msg = await anthropic.messages.create({
    model: 'claude-sonnet-5-5',
    max_tokens: 2048,
    messages: [{ role: 'user', content: String(req.body.prompt) }],
  });
  res.status(200).json(msg);
}
