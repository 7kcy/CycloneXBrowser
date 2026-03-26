const express  = require('express');
const path     = require('path');
const https    = require('https');

const app  = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── AI Search Proxy ──────────────────────────────────────
app.post('/api/search', (req, res) => {
  const { query } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'Missing query' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      error: 'ANTHROPIC_API_KEY not set. See setup instructions in README.'
    });
  }

  const systemPrompt = `You are Cyclone X, a sleek and powerful AI search assistant.
When the user asks a question or searches for something:
- Give a comprehensive, well-structured answer.
- Use **bold** for key terms and important phrases.
- Use bullet points or numbered lists for multi-part answers where appropriate.
- Keep your tone confident, clear, and informative.
- If the topic involves recent events beyond your knowledge, note that clearly.
- Format your response in clean HTML using only: <p>, <strong>, <ul>, <ol>, <li>, <h3>, <code>.
- Do NOT use markdown — only clean HTML tags listed above.
- Aim for a thorough but concise response (150–400 words).`;

  const body = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1000,
    system: systemPrompt,
    messages: [{ role: 'user', content: query }]
  });

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
      'Content-Length':    Buffer.byteLength(body)
    }
  };

  const apiReq = https.request(options, (apiRes) => {
    let data = '';
    apiRes.on('data', chunk => data += chunk);
    apiRes.on('end', () => {
      try {
        const parsed = JSON.parse(data);
        if (parsed.error) return res.status(500).json({ error: parsed.error.message });
        const text = parsed.content?.find(b => b.type === 'text')?.text || '<p>No response.</p>';
        res.json({ result: text });
      } catch (e) {
        res.status(500).json({ error: 'Failed to parse API response.' });
      }
    });
  });

  apiReq.on('error', (e) => res.status(500).json({ error: e.message }));
  apiReq.write(body);
  apiReq.end();
});

// ── Serve frontend for all other routes ─────────────────
app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🌀 Cyclone X running at http://localhost:${PORT}\n`);
});
