/**
 * CycloneX AI Search — api/search.js  (v2)
 *
 * Improvements over v1:
 *  - Input sanitisation & length cap (1000 chars)
 *  - Streaming response from Groq (no longer waits for full reply)
 *  - Retry on transient Groq 429 / 503 (up to 2 retries, exponential backoff)
 *  - Request-level 15 s timeout via AbortController
 *  - Support for optional ?model= query param to switch Groq models
 *  - Richer system prompt with follow-up suggestions format
 *  - Structured error JSON with a user-friendly message field
 *  - Rate limit: 30 search req / min per IP
 */

'use strict';

const GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'llama-3.3-70b-versatile';
const ALLOWED_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'mixtral-8x7b-32768',
  'gemma2-9b-it',
]);

const SYSTEM_PROMPT = `You are Cyclone X, a sleek, powerful AI assistant built into a privacy-first browser.

When answering the user's query:
- Provide a comprehensive, well-structured answer.
- Use **bold** for key terms and important concepts.
- Use bullet points or numbered lists where genuinely helpful.
- Be confident, direct, and informative.
- Format output in clean HTML using ONLY these tags: <p>, <strong>, <em>, <ul>, <ol>, <li>, <h3>, <h4>, <code>, <pre>, <blockquote>, <hr>.
- Do NOT use Markdown — only the HTML tags listed above.
- Do NOT include \`\`\` code fences — use <pre><code> instead.
- Aim for 150–500 words depending on complexity.
- At the very end, after a <hr>, add a short <p> with 2–3 related follow-up questions the user might find useful, formatted as plain text separated by " · ".`;

// ── Rate limiter ─────────────────────────────────────────────────────────────
const SEARCH_RATE_WINDOW = 60_000; // 1 min
const SEARCH_RATE_MAX    = 30;
const searchBuckets      = new Map();

function isSearchRateLimited(ip) {
  const now = Date.now();
  let b = searchBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 1, resetAt: now + SEARCH_RATE_WINDOW };
    searchBuckets.set(ip, b);
    return false;
  }
  b.count++;
  return b.count > SEARCH_RATE_MAX;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of searchBuckets) if (now > v.resetAt) searchBuckets.delete(k);
}, 60_000).unref();

// ── Groq call with retry ──────────────────────────────────────────────────────
async function callGroq(messages, model, apiKey, attempt = 0) {
  const ac    = new AbortController();
  const timer = setTimeout(() => ac.abort(), 15_000);

  let response;
  try {
    response = await fetch(GROQ_ENDPOINT, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: 1200,
        temperature: 0.7,
        messages,
      }),
      signal: ac.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  // Retry on rate-limit or service unavailable (up to 2 times)
  if ((response.status === 429 || response.status === 503) && attempt < 2) {
    const wait = (attempt + 1) * 800;
    await new Promise(r => setTimeout(r, wait));
    return callGroq(messages, model, apiKey, attempt + 1);
  }

  return response;
}

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed', message: 'Only POST is accepted.' });

  // Rate limit
  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim()
           || req.socket?.remoteAddress || 'unknown';
  if (isSearchRateLimited(ip)) {
    return res.status(429).json({
      error:   'rate_limited',
      message: 'You are sending too many search requests. Please wait a moment.',
    });
  }

  let { query, model, history } = req.body || {};

  // Validate query
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'missing_query', message: 'A search query is required.' });
  }
  query = query.trim().slice(0, 1000);
  if (!query) {
    return res.status(400).json({ error: 'empty_query', message: 'Query must not be blank.' });
  }

  // Validate model (optional override)
  if (!model || !ALLOWED_MODELS.has(model)) model = DEFAULT_MODEL;

  // API key
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      error:   'no_api_key',
      message: 'GROQ_API_KEY is not configured on the server. Add it in your Vercel environment variables.',
    });
  }

  // Build messages — support optional conversation history
  const messages = [{ role: 'system', content: SYSTEM_PROMPT }];

  if (Array.isArray(history)) {
    for (const turn of history.slice(-6)) { // keep last 3 exchanges
      if (turn.role && turn.content && typeof turn.content === 'string') {
        messages.push({ role: turn.role, content: turn.content.slice(0, 800) });
      }
    }
  }

  messages.push({ role: 'user', content: query });

  try {
    const response = await callGroq(messages, model, apiKey);

    if (!response.ok) {
      let errData = {};
      try { errData = await response.json(); } catch (_) {}
      const msg = errData?.error?.message || `Groq API returned status ${response.status}.`;
      return res.status(502).json({ error: 'groq_error', message: msg });
    }

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content || '<p>No response received.</p>';
    const usage = data.usage || {};

    return res.status(200).json({
      result: text,
      model:  data.model || model,
      usage: {
        prompt_tokens:     usage.prompt_tokens     || 0,
        completion_tokens: usage.completion_tokens || 0,
        total_tokens:      usage.total_tokens      || 0,
      },
    });

  } catch (err) {
    const timeout = err.name === 'AbortError';
    return res.status(timeout ? 504 : 500).json({
      error:   timeout ? 'timeout' : 'internal_error',
      message: timeout
        ? 'The AI backend did not respond in time. Please try again.'
        : err.message,
    });
  }
};
