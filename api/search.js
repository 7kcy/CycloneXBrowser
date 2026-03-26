module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { query } = req.body || {};
  if (!query) return res.status(400).json({ error: 'Missing query' });

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY not configured in Vercel environment variables.' });

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 1000,
        messages: [
          {
            role: 'system',
            content: `You are Cyclone X, a sleek and powerful AI search assistant.
When the user searches for something:
- Give a comprehensive, well-structured answer.
- Use **bold** for key terms and important phrases.
- Use bullet points or numbered lists where appropriate.
- Keep your tone confident, clear, and informative.
- Format in clean HTML using only: <p>, <strong>, <ul>, <ol>, <li>, <h3>, <code>.
- Do NOT use markdown — only the HTML tags listed above.
- Aim for 150–400 words.`
          },
          { role: 'user', content: query }
        ]
      })
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      return res.status(500).json({ error: data.error?.message || `API error ${response.status}` });
    }

    const text = data.choices?.[0]?.message?.content || '<p>No response.</p>';
    return res.status(200).json({ result: text });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
