// VULNERABLE: Vite inlines every VITE_* variable into the client bundle.
export async function chat(prompt: string): Promise<unknown> {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${import.meta.env.VITE_OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ model: import.meta.env.VITE_OPENAI_MODEL, messages: [{ role: 'user', content: prompt }] }),
  });
  return res.json();
}
