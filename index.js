'use strict';

// ── State ────────────────────────────────────────────────
let currentTheme = 'dark';
let recognition  = null;
let isListening  = false;

// ── Init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadPreferences();
  document.getElementById('homeInput').focus();
  document.addEventListener('keydown', e => { if (e.altKey && e.key === 'v') startVoice(); });
});

// ── Preferences ──────────────────────────────────────────
function loadPreferences() {
  const savedTheme = localStorage.getItem('cx-theme') || 'dark';
  setTheme(savedTheme, true);
}

function savePreferences() {
  localStorage.setItem('cx-theme', currentTheme);
}

// ── Theme ─────────────────────────────────────────────────
function setTheme(theme, silent = false) {
  currentTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  document.getElementById('darkBtn').classList.toggle('active', theme === 'dark');
  document.getElementById('lightBtn').classList.toggle('active', theme === 'light');
  if (!silent) savePreferences();
}

// ── Settings ──────────────────────────────────────────────
function openSettings() {
  document.getElementById('settingsPanel').classList.add('open');
  document.getElementById('settingsOverlay').classList.add('open');
}

function closeSettings() {
  document.getElementById('settingsPanel').classList.remove('open');
  document.getElementById('settingsOverlay').classList.remove('open');
}

// ── Navigation ────────────────────────────────────────────
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

// ── Search Entry Points ───────────────────────────────────
function handleKey(event, source) {
  if (event.key === 'Enter') {
    source === 'home' ? doSearch() : doSearchFromResults();
  }
}

function doSearch() {
  const q = document.getElementById('homeInput').value.trim();
  if (q) runSearch(q);
}

function doSearchFromResults() {
  const q = document.getElementById('resultsInput').value.trim();
  if (q) runSearch(q);
}

function quickSearch(query) {
  document.getElementById('homeInput').value = query;
  runSearch(query);
}

// ── Core Search (calls local server) ─────────────────────
async function runSearch(query) {
  showResults();
  document.getElementById('resultsInput').value = query;
  document.getElementById('queryLabel').textContent = `Results for: "${query}"`;
  document.getElementById('resultsContainer').innerHTML = loadingHTML();
  window.scrollTo({ top: 0 });

  try {
    const res = await fetch('/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });

    const data = await res.json();

    if (!res.ok || data.error) {
      throw new Error(data.error || `Server error ${res.status}`);
    }

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    document.getElementById('resultsContainer').innerHTML = `
      <div class="result-card">
        <div class="result-card-header">
          <span class="result-badge ai-badge">⚡ AI Answer</span>
          <span class="result-badge">Cyclone X</span>
        </div>
        <div class="result-content">${data.result}</div>
        <div class="result-footer">
          <span class="result-footer-text">Generated at ${timestamp} · Powered by Claude</span>
        </div>
      </div>
      ${suggestionsCard(query)}
    `;
  } catch (err) {
    renderError(err.message || 'Something went wrong.');
  }
}

// ── Suggestions ───────────────────────────────────────────
function suggestionsCard(query) {
  const words = query.toLowerCase().split(' ');
  const base  = words.slice(0, 3).join(' ');
  const suggestions = new Set([
    `How does ${base} work`,
    `What is ${base}`,
    `${base} explained`,
    `Best ${base} examples`,
    `${base} 2025`
  ]);
  suggestions.delete(query);

  const chips = [...suggestions].slice(0, 5).map(s =>
    `<button class="chip" onclick="quickSearch('${escAttr(s)}')">${escHTML(s)}</button>`
  ).join('');

  return `
    <div class="result-card" style="margin-top:12px;">
      <div class="result-card-header"><span class="result-badge">Related Searches</span></div>
      <div class="quick-chips" style="justify-content:flex-start;">${chips}</div>
    </div>
  `;
}

// ── Loading / Error ───────────────────────────────────────
function loadingHTML() {
  return `
    <div class="loading-state">
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
      <span style="font-size:11px;opacity:0.6;margin-top:4px;display:block;">${escHTML(msg)}</span>
    </div>
  `;
}

// ── Voice Search ──────────────────────────────────────────
function startVoice() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) { alert('Voice search requires Chrome or Edge.'); return; }
  if (isListening) { stopVoice(); return; }

  recognition = new SR();
  recognition.lang = 'en-US';
  recognition.interimResults = false;

  recognition.onstart  = () => {
    isListening = true;
    document.getElementById('voiceIndicator').classList.remove('hidden');
  };
  recognition.onresult = e => {
    const t = e.results[0][0].transcript;
    document.getElementById('homeInput').value = t;
    stopVoice();
    runSearch(t);
  };
  recognition.onerror  = () => stopVoice();
  recognition.onend    = () => stopVoice();
  recognition.start();
}

function stopVoice() {
  isListening = false;
  document.getElementById('voiceIndicator').classList.add('hidden');
  if (recognition) { recognition.stop(); recognition = null; }
}

// ── Utils ─────────────────────────────────────────────────
function escHTML(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(s) {
  return String(s).replace(/'/g,"\\'");
}
