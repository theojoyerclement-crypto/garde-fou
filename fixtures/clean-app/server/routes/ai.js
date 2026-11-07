// Protected by the auth middleware mounted in server/app.js.
const express = require('express');
const OpenAI = require('openai');

const router = express.Router();
const openai = new OpenAI();

router.post('/summarize', async (req, res) => {
  const r = await openai.responses.create({ model: 'gpt-4o-mini', input: req.body.text });
  res.json({ summary: r.output_text });
});

module.exports = router;
