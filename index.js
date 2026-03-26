/* ═══════════════════════════════════════════════════════
   Cyclone X — index.js
   AI-powered search engine frontend
   ═══════════════════════════════════════════════════════ */

'use strict';

// ── State ────────────────────────────────────────────────
let currentTheme = 'dark';
let currentMode  = 'ai';       // 'ai' | 'web'
let recognition  = null;
let isListening  = false;

// ── Init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadPreferences();
  document.getElementById('homeInput').focus();

  // Alt+V voice shortcut
  document.addEventListener('keydown', (e) => {
    if (e.altKey && e.key === 'v') startVoice();
  });
});

// ── Preferences ─────────────────────────────────────────
function loadPreferences() {
  const savedTheme = localStorage.getItem('cx-theme') || 'dark';
  const savedMode  = localStorage.getItem('cx-mode')  || 'ai';
  setTheme(savedTheme, true);
  setMode(savedMode, true);
}

function savePreferences() {
  localStorage.setItem('cx-theme', currentTheme);
  localStorage.setItem('cx-mode',  currentMode);
}

// ── Theme ────────────────────────────────────────────────
function setTheme(theme, silent = false) {
  currentTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);

  document.getElementById('darkBtn').classList.toggle('active', theme === 'dark');
  document.getElementById('lightBtn').classList.toggle('active', theme === 'light');

  if (!silent) savePreferences();
}

// ── Mode ─────────────────────────────────────────────────
function setMode(mode, silent = false) {
  currentMode = mode;
  document.getElementById('aiBtn').classList.toggle('active', mode === 'ai');
  document.getElementById('webBtn').classList.toggle('active', mode === 'web');
  if (!silent) savePreferences();
}

// ── Settings Panel ───────────────────────────────────────
function openSettings() {
  document.getElementById('settingsPanel').classList.add('open');
  document.getElementById('settingsOverlay').classList.add('open');
}

function closeSettings() {
  document.getElementById('settingsPanel').classList.remove('open');
  document.getElementById('settingsOverlay').classList.remove('open');
}

// ── Navigation ───────────────────────────────────────────
function goHome() {
  document.getElementById('resultsScreen').classList.add('hidden');
  document.getElementById('homeScreen').classList.remove('hidden');
  document.getElementById('homeInput').value = '';
  document.getElementById('homeInput').focus();
}

function showResults() {
  document.getElementById('homeScreen').classList.add('hidden');
  document.getElementById('resultsScreen').classList.remove('hidden');
}

// ── Search Entry Points ──────────────────────────────────
function handleKey(event, source) {
  if (event.key === 'Enter') {
    if (source === 'home') doSearch();
    else doSearchFromResults();
  }
}

function doSearch() {
  const query = document.getElementById('homeInput').value.trim();
  if (!query) return;
  runSearch(query);
}

function doSearchFromResults() {
  const query = document.getElementById('resultsInput').value.trim();
  if (!query) return;
  runSearch(query);
}

function quickSearch(query) {
  document.getElementById('homeInput').value = query;
  runSearch(query);
}

// ── Core Search ──────────────────────────────────────────
async function runSearch(query) {
  showResults();
  document.getElementById('resultsInput').value = query;
  document.getElementById('queryLabel').textContent = `Results for: "${query}"`;
  document.getElementById('resultsContainer').innerHTML = loadingHTML();

  window.scrollTo({ top: 0 });

  try {
    if (currentMode === 'web') {
      renderWebLinks(query);
    } else {
      await runAISearch(query);
    }
  } catch (err) {
    renderError(err.message || 'Something went wrong.');
  }
}

// ── AI Search (Anthropic API) ────────────────────────────
async function runAISearch(query) {
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

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: systemPrompt,
      messages: [{ role: 'user', content: query }]
    })
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error?.message || `API error ${response.status}`);
  }

  const data = await response.json();
  const textBlock = data.content?.find(b => b.type === 'text');
  const html = textBlock?.text || '<p>No response received.</p>';

  const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  document.getElementById('resultsContainer').innerHTML = `
    <div class="result-card">
      <div class="result-card-header">
        <span class="result-badge ai-badge">⚡ AI Answer</span>
        <span class="result-badge">Cyclone X</span>
      </div>
      <div class="result-content">${html}</div>
      <div class="result-footer">
        <span class="result-footer-text">Generated at ${timestamp} · Powered by Claude</span>
      </div>
    </div>
    ${suggestionsCard(query)}
  `;
}

// ── Web Links Mode ───────────────────────────────────────
function renderWebLinks(query) {
  const encoded = encodeURIComponent(query);
  const engines = [
    { name: 'Google',    url: `https://www.google.com/search?q=${encoded}`,          icon: 'G' },
    { name: 'Bing',      url: `https://www.bing.com/search?q=${encoded}`,            icon: 'B' },
    { name: 'DuckDuckGo',url: `https://duckduckgo.com/?q=${encoded}`,                icon: 'D' },
    { name: 'Wikipedia', url: `https://en.wikipedia.org/wiki/Special:Search/${encoded}`, icon: 'W' },
    { name: 'Reddit',    url: `https://www.reddit.com/search/?q=${encoded}`,         icon: 'R' },
    { name: 'YouTube',   url: `https://www.youtube.com/results?search_query=${encoded}`, icon: 'Y' },
  ];

  const links = engines.map(e => `
    <a href="${e.url}" target="_blank" rel="noopener" class="web-link-item">
      <span class="web-link-icon">${e.icon}</span>
      <span class="web-link-name">${e.name}</span>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-left:auto;opacity:0.4">
        <line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/>
      </svg>
    </a>
  `).join('');

  document.getElementById('resultsContainer').innerHTML = `
    <div class="result-card">
      <div class="result-card-header">
        <span class="result-badge">⊞ Web Links</span>
      </div>
      <p style="font-size:13px;color:var(--text-3);font-family:var(--font-mono);margin-bottom:16px;">
        Search "${query}" across the web:
      </p>
      <div class="web-links-grid">${links}</div>
    </div>
    ${suggestionsCard(query)}
  `;

  injectWebLinkStyles();
}

function injectWebLinkStyles() {
  if (document.getElementById('wl-styles')) return;
  const s = document.createElement('style');
  s.id = 'wl-styles';
  s.textContent = `
    .web-links-grid { display: flex; flex-direction: column; gap: 6px; }
    .web-link-item {
      display: flex; align-items: center; gap: 12px;
      padding: 12px 14px;
      background: var(--bg-3);
      border: 1px solid var(--border);
      border-radius: 8px;
      text-decoration: none;
      color: var(--text-2);
      font-family: var(--font-display);
      font-size: 14px;
      transition: all 0.15s ease;
    }
    .web-link-item:hover {
      background: var(--surface-2);
      border-color: var(--border-2);
      color: var(--text);
      transform: translateX(3px);
    }
    .web-link-icon {
      width: 24px; height: 24px;
      background: var(--surface-2);
      border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      font-weight: 700;
      font-size: 11px;
      color: var(--text-3);
      flex-shrink: 0;
    }
  `;
  document.head.appendChild(s);
}

// ── Suggestions Card ─────────────────────────────────────
function suggestionsCard(query) {
  const words = query.toLowerCase().split(' ');
  const suggestions = generateSuggestions(words, query);

  const chips = suggestions.map(s =>
    `<button class="chip" onclick="quickSearch('${escapeAttr(s)}')">${escapeHTML(s)}</button>`
  ).join('');

  return `
    <div class="result-card" style="margin-top:12px;">
      <div class="result-card-header">
        <span class="result-badge">Related Searches</span>
      </div>
      <div class="quick-chips" style="justify-content:flex-start;">${chips}</div>
    </div>
  `;
}

function generateSuggestions(words, original) {
  const prefixes = ['How does', 'What is', 'Why is', 'Best', 'Latest'];
  const suffixes = ['explained', 'tutorial', 'examples', '2025', 'guide'];
  const base = words.slice(0, 3).join(' ');
  const s = new Set();

  prefixes.forEach(p => s.add(`${p} ${base}`));
  suffixes.forEach(suf => s.add(`${base} ${suf}`));
  s.delete(original);

  return [...s].slice(0, 5);
}

// ── Loading HTML ─────────────────────────────────────────
function loadingHTML() {
  return `
    <div class="loading-state" id="loadingState">
      <div class="spinner"></div>
      <span>Cyclone X is thinking…</span>
    </div>
  `;
}

function renderError(msg) {
  document.getElementById('resultsContainer').innerHTML = `
    <div class="error-card">
      <span>⚡</span>
      Something went wrong.<br/>
      <span style="font-size:11px;opacity:0.6;margin-top:4px;display:block;">${escapeHTML(msg)}</span>
    </div>
  `;
}

// ── Voice Search ─────────────────────────────────────────
function startVoice() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) {
    alert('Voice search is not supported in this browser. Try Chrome.');
    return;
  }

  if (isListening) { stopVoice(); return; }

  recognition = new SpeechRecognition();
  recognition.lang = 'en-US';
  recognition.interimResults = false;
  recognition.maxAlternatives = 1;

  recognition.onstart = () => {
    isListening = true;
    document.getElementById('voiceIndicator').classList.remove('hidden');
  };

  recognition.onresult = (e) => {
    const transcript = e.results[0][0].transcript;
    document.getElementById('homeInput').value = transcript;
    stopVoice();
    runSearch(transcript);
  };

  recognition.onerror = (e) => {
    console.warn('Voice error:', e.error);
    stopVoice();
  };

  recognition.onend = () => stopVoice();

  recognition.start();
}

function stopVoice() {
  isListening = false;
  document.getElementById('voiceIndicator').classList.add('hidden');
  if (recognition) { recognition.stop(); recognition = null; }
}

// ── Utils ────────────────────────────────────────────────
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return String(str).replace(/'/g, "\\'");
}
