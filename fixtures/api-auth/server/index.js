const express = require('express');
const OpenAI = require('openai');

const app = express();
const openai = new OpenAI();
app.use(express.json());

app.post('/api/summarize', async (req, res) => {
  const r = await openai.responses.create({ model: 'gpt-4o-mini', input: req.body.text });
  res.json({ summary: r.output_text });
});

app.listen(3000);
