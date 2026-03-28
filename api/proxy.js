/**
 * CycloneX Proxy — api/proxy.js (v4 — definitive)
 *
 * Root cause of CSS not loading:
 *  - Modern sites (DDG, etc) inject <link>/<script> tags via setAttribute(),
 *    innerHTML, or insertAdjacentHTML — NOT via createElement().href/src
 *  - These bypassed all previous rewriting
 *
 * This version patches:
 *  - Element.prototype.setAttribute (catches ALL attr sets on ANY element)
 *  - Element.prototype.insertAdjacentHTML (catches HTML injection)
 *  - document.write (catches old-school injection)
 *  - document.createElement (catches property sets before insertion)
 *  - MutationObserver (catches anything that slips through)
 *  - fetch + XHR (proxify API calls)
 */

'use strict';

const { promisify } = require('util');
const zlib = require('zlib');

const gunzip           = promisify(zlib.gunzip);
const inflateRaw       = promisify(zlib.inflateRaw);
const brotliDecompress = promisify(zlib.brotliDecompress);

// ── Rate limiter ──────────────────────────────────────────────────────────────
const RATE_WINDOW_MS = 10_000;
const RATE_MAX       = 150;
const rateBuckets    = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) { b = { count: 1, resetAt: now + RATE_WINDOW_MS }; rateBuckets.set(ip, b); return false; }
  b.count++;
  return b.count > RATE_MAX;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k); }, 30_000).unref();

// ── SSRF blocklist ────────────────────────────────────────────────────────────
const BLOCKED_HOSTS = new Set(['localhost','127.0.0.1','0.0.0.0','::1','metadata.google.internal','169.254.169.254']);
function isBlockedHost(h) {
  h = h.toLowerCase();
  if (BLOCKED_HOSTS.has(h)) return true;
  const p = h.split('.');
  if (p[0]==='10') return true;
  if (p[0]==='192'&&p[1]==='168') return true;
  if (p[0]==='172') { const n=parseInt(p[1],10); if (n>=16&&n<=31) return true; }
  return false;
}

// ── URL helpers ───────────────────────────────────────────────────────────────
function normaliseUrl(raw) {
  let u = raw.trim();
  try { u = decodeURIComponent(u); } catch(_) {}
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  const parsed = new URL(u);
  return { url: parsed.href, parsed };
}

// ── Decompression ─────────────────────────────────────────────────────────────
async function decompress(buf, enc) {
  enc = (enc||'').toLowerCase().trim();
  try {
    if (enc==='gzip'||enc==='x-gzip') return await gunzip(buf);
    if (enc==='deflate')              return await inflateRaw(buf);
    if (enc==='br')                   return await brotliDecompress(buf);
  } catch(_) {}
  return buf;
}

// ── Proxy URL builder ─────────────────────────────────────────────────────────
const PROXY_PATH = '/api/proxy?url=';
// proxyUrl for server-side rewriting — needs absolute origin injected at call time
function proxyUrl(url, base, origin) {
  if (!url) return null;
  const s = url.trim();
  if (!s || /^(data:|javascript:|blob:|about:|#|mailto:|tel:)/i.test(s)) return null;
  try {
    const prefix = origin ? origin + PROXY_PATH : PROXY_PATH;
    return prefix + encodeURIComponent(new URL(s, base).href);
  } catch(_) { return null; }
}

// ── Attribute rewriter (server-side HTML) ────────────────────────────────────
function rewriteAttr(html, tag, attr, base, origin) {
  const re = new RegExp(`(<${tag}(?:\\s[^>]*)?)\\s${attr}=(["'])([^"']*?)\\2`, 'gi');
  return html.replace(re, (m, pre, q, url) => {
    const p = proxyUrl(url, base, origin);
    return p ? `${pre} ${attr}=${q}${p}${q}` : m;
  });
}

function rewriteSrcset(html, base, origin) {
  return html.replace(/(\ssrcset=)(["'])([^"']+)(\2)/gi, (_m, pre, q, val, qc) => {
    const rw = val.replace(/([^\s,][^\s,]*?)(\s+[\d.]+[wx])?(?=\s*,|\s*$)/g, (part, url, desc) => {
      if (!url) return part;
      const p = proxyUrl(url.trim(), base, origin);
      return p ? (p + (desc||'')) : part;
    });
    return `${pre}${q}${rw}${qc}`;
  });
}

// ── CSS rewriter — base must be the CSS file's own URL ───────────────────────
function rewriteCssUrls(css, cssBase, origin) {
  return css
    .replace(/url\(\s*(["']?)([^)"'\s]+)\1\s*\)/gi, (_m, q, url) => {
      const p = proxyUrl(url, cssBase, origin); return p ? `url('${p}')` : _m;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (_m, _q, url) => {
      const p = proxyUrl(url, cssBase, origin); return p ? `@import '${p}'` : _m;
    })
    .replace(/@import\s+url\(\s*(["']?)([^)"'\s]+)\1\s*\)/gi, (_m, _q, url) => {
      const p = proxyUrl(url, cssBase, origin); return p ? `@import url('${p}')` : _m;
    });
}

// ── Strip headers ─────────────────────────────────────────────────────────────
const STRIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'x-frame-options','x-content-type-options','strict-transport-security',
  'permissions-policy','cross-origin-embedder-policy','cross-origin-opener-policy',
  'cross-origin-resource-policy','report-to','nel','expect-ct','content-encoding',
  'x-xss-protection','referrer-policy','origin-agent-cluster','document-policy','feature-policy',
]);

function applyCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin',      '*');
  res.setHeader('Access-Control-Allow-Methods',     'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers',     '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Cross-Origin-Resource-Policy',     'cross-origin');
  res.setHeader('Cross-Origin-Embedder-Policy',     'unsafe-none');
  res.setHeader('Cross-Origin-Opener-Policy',       'unsafe-none');
  res.setHeader('X-Frame-Options',                  'ALLOWALL');
  res.setHeader('Content-Security-Policy',          '');
}

function guessType(url, serverType) {
  if (serverType && !serverType.includes('octet-stream') && !serverType.includes('plain')) return serverType;
  const u = url.split('?')[0].toLowerCase();
  if (u.endsWith('.css'))               return 'text/css';
  if (u.endsWith('.js')||u.endsWith('.mjs')) return 'application/javascript';
  if (u.endsWith('.html')||u.endsWith('.htm')) return 'text/html';
  if (u.endsWith('.json'))              return 'application/json';
  if (u.endsWith('.svg'))               return 'image/svg+xml';
  return serverType || 'application/octet-stream';
}

// ── Injected rewriter script ──────────────────────────────────────────────────
function buildRewriterScript(targetUrl, origin) {
  const safe = s => s.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  return `<script data-cx-rewriter>
(function(){
'use strict';
var PROXY='${safe(origin)}${PROXY_PATH}',PAGE_URL='${safe(targetUrl)}';

function toAbs(h){
  if(!h||typeof h!=='string')return null;
  h=h.trim();
  if(/^(javascript:|#|data:|mailto:|tel:|blob:|about:)/i.test(h))return null;
  try{return new URL(h,PAGE_URL).href;}catch(e){return null;}
}
function px(url){var a=toAbs(url);return a?PROXY+encodeURIComponent(a):null;}

// Which attributes carry resource URLs
var SRC_ATTRS  = {src:1, href:1, action:1, poster:1, 'data-src':1, 'data-lazy-src':1, 'data-original':1};
var SRC_TAGS   = {img:1,script:1,link:1,iframe:1,video:1,audio:1,source:1,track:1,embed:1,object:1,form:1};

// ── Core: patch Element.prototype.setAttribute ───────────────────────────────
// This catches EVERY setAttribute call on ANY element, which is how most
// modern frameworks (React, Vue, Angular, Svelte) set resource URLs
var _setAttr = Element.prototype.setAttribute;
Element.prototype.setAttribute = function(name, value) {
  var n = name && name.toLowerCase();
  var t = this.tagName && this.tagName.toLowerCase();
  if (SRC_ATTRS[n] && (SRC_TAGS[t] || n==='href' || n==='src')) {
    var p = px(value);
    if (p) { _setAttr.call(this, name, p); return; }
  }
  _setAttr.call(this, name, value);
};

// ── Patch .src and .href property setters on prototypes ──────────────────────
function patchProto(proto, prop) {
  var desc = Object.getOwnPropertyDescriptor(proto, prop);
  if (!desc || !desc.set) return;
  var origSet = desc.set, origGet = desc.get;
  Object.defineProperty(proto, prop, {
    set: function(v) { var p=px(v); origSet.call(this, p||v); },
    get: origGet,
    configurable: true
  });
}
patchProto(HTMLScriptElement.prototype,  'src');
patchProto(HTMLImageElement.prototype,   'src');
patchProto(HTMLIFrameElement.prototype,  'src');
patchProto(HTMLLinkElement.prototype,    'href');
patchProto(HTMLSourceElement.prototype,  'src');

// ── Patch insertAdjacentHTML ──────────────────────────────────────────────────
var _iah = Element.prototype.insertAdjacentHTML;
Element.prototype.insertAdjacentHTML = function(pos, html) {
  _iah.call(this, pos, rewriteHtmlSnippet(html));
};

// ── Patch innerHTML setter ────────────────────────────────────────────────────
var _inHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
if (_inHTMLDesc && _inHTMLDesc.set) {
  var _inSet = _inHTMLDesc.set;
  Object.defineProperty(Element.prototype, 'innerHTML', {
    set: function(v) { _inSet.call(this, rewriteHtmlSnippet(v)); },
    get: _inHTMLDesc.get,
    configurable: true
  });
}

// Simple HTML snippet rewriter for dynamic injection
function rewriteHtmlSnippet(html) {
  if (!html || typeof html !== 'string') return html;
  // Match src/href/action attrs with double or single quotes separately (no backreference needed)
  function rwAttrQ(h, q) {
    var re = new RegExp('([\\s(](?:src|href|action)=)(' + q + ')([^' + q + ']+)' + q, 'gi');
    return h.replace(re, function(m, pre, qq, url) {
      var p = px(url); return p ? pre+qq+p+qq : m;
    });
  }
  return rwAttrQ(rwAttrQ(html, '"'), "'");
}

// ── fetch ─────────────────────────────────────────────────────────────────────
var _fetch = window.fetch.bind(window);
window.fetch = function(input, init) {
  var url = typeof input==='string' ? input : (input&&input.url ? input.url : '');
  var a = toAbs(url);
  if (a && !a.startsWith(location.origin)) {
    input = PROXY+encodeURIComponent(a);
    init = Object.assign({}, init||{}, {credentials:'omit', mode:'cors'});
  }
  return _fetch(input, init);
};

// ── XHR ───────────────────────────────────────────────────────────────────────
var _open = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
  var a = toAbs(url);
  if (a && !a.startsWith(location.origin)) url = PROXY+encodeURIComponent(a);
  return _open.call(this, method, url, async!==false, user, pass);
};

// ── <a> clicks ────────────────────────────────────────────────────────────────
document.addEventListener('click', function(e) {
  var el = e.target.closest('a[href]'); if (!el) return;
  var href = el.getAttribute('href');
  if (!href || /^(javascript:|#|mailto:|tel:)/i.test(href)) return;
  var a = toAbs(href); if (!a) return;
  e.preventDefault(); e.stopPropagation();
  window.parent.postMessage({type:'cx-navigate', url:a}, '*');
}, true);

// ── <form> submits ────────────────────────────────────────────────────────────
document.addEventListener('submit', function(e) {
  var form = e.target; if (!form || form.tagName!=='FORM') return;
  e.preventDefault(); e.stopPropagation();
  var action = form.getAttribute('action') || PAGE_URL;
  var method = (form.getAttribute('method')||'GET').toUpperCase();
  var a = toAbs(action) || PAGE_URL;
  var params = new URLSearchParams(new FormData(form));
  if (method==='GET') window.parent.postMessage({type:'cx-navigate', url:a.split('?')[0]+'?'+params}, '*');
  else window.parent.postMessage({type:'cx-navigate', url:a, method:'POST', body:params.toString()}, '*');
}, true);

// ── history ───────────────────────────────────────────────────────────────────
['pushState','replaceState'].forEach(function(fn) {
  var orig = history[fn].bind(history);
  history[fn] = function(state, title, url) {
    if (!url) { try{orig(state,title,url);}catch(e){} return; }
    var a = toAbs(String(url));
    if (a) { try{orig(state,title,PROXY+encodeURIComponent(a));}catch(e){window.parent.postMessage({type:'cx-navigate',url:a},'*');} }
    else { try{orig(state,title,url);}catch(e){} }
  };
});

// ── MutationObserver: last-resort catch for anything that slips through ───────
function rewriteNode(node) {
  if (node.nodeType !== 1) return;
  var tag = (node.tagName||'').toLowerCase();
  // Check resource attributes
  ['src','href','data-src','data-lazy-src','data-original'].forEach(function(a) {
    var v = node.getAttribute && node.getAttribute(a);
    if (v && !v.startsWith(PROXY)) { var p=px(v); if(p) _setAttr.call(node,a,p); }
  });
  // Recurse into subtree
  if (node.querySelectorAll) {
    node.querySelectorAll('[src],[href],[data-src],[data-lazy-src]').forEach(rewriteNode);
  }
}
new MutationObserver(function(ms) {
  ms.forEach(function(m) { m.addedNodes.forEach(rewriteNode); });
}).observe(document.documentElement, {childList:true, subtree:true});

// ── Parent messages ───────────────────────────────────────────────────────────
window.addEventListener('message', function(e) {
  if (e.data && e.data.type==='cx-scroll-to') { try{window.scrollTo(e.data.x||0,e.data.y||0);}catch(_){} }
});
})();
<\/script>`;
}

// ── Error page ────────────────────────────────────────────────────────────────
function errorPage(msg, target, status) {
  const s=String(msg).replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const t=String(target||'').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const j=String(target||'').replace(/'/g,"\\'");
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Proxy Error</title>
<style>*{box-sizing:border-box}body{margin:0;font-family:monospace;background:#080808;color:#ff6060;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#111;border:1px solid #2a2a2a;border-radius:14px;padding:40px;max-width:540px;width:92%}h2{margin:0 0 20px;color:#ff8585}.label{color:#555;font-size:10px;text-transform:uppercase;margin-top:20px}.code{background:#1a1a1a;border:1px solid #222;border-radius:7px;padding:12px;margin-top:6px;color:#fc9;font-size:12px;word-break:break-all}button{margin-top:24px;background:#1e90ff;color:#fff;border:none;border-radius:9px;padding:11px 22px;cursor:pointer}.status{background:#ff3030;color:#fff;border-radius:5px;padding:2px 9px;font-size:11px;margin-bottom:10px;display:inline-block}</style></head>
<body><div class="card"><div class="status">${status}</div><h2>⚡ Proxy Error</h2><div class="label">What happened</div><div class="code">${s}</div><div class="label">Target URL</div><div class="code">${t}</div>${target?`<button onclick="window.parent.postMessage({type:'cx-navigate',url:'${j}'},'*')">↩ Retry</button>`:''}</div></body></html>`;
}

function guessTypeFromUrl(url, serverType) {
  if (serverType && !serverType.includes('octet-stream') && !serverType.includes('plain')) return serverType;
  const u = url.split('?')[0].toLowerCase();
  if (u.endsWith('.css'))                return 'text/css';
  if (u.endsWith('.js')||u.endsWith('.mjs')) return 'application/javascript';
  if (u.endsWith('.html')||u.endsWith('.htm')) return 'text/html';
  if (u.endsWith('.json'))               return 'application/json';
  if (u.endsWith('.svg'))                return 'image/svg+xml';
  return serverType || 'application/octet-stream';
}

// ── Main handler ──────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS,HEAD');
  res.setHeader('Access-Control-Allow-Headers','*');
  if (req.method==='OPTIONS') return res.status(200).end();

  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(ip)) return res.status(429).send(errorPage('Too many requests.','',429));

  // Derive absolute origin so CSS/HTML rewrites produce absolute proxy URLs
  const reqOrigin = (() => {
    const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
    const host  = req.headers['x-forwarded-host'] || req.headers.host || '';
    return host ? `${proto}://${host}` : '';
  })();

  let targetUrl, parsedUrl;
  try {
    const raw = req.query.url||'';
    if (!raw) return res.status(400).send(errorPage('Missing ?url=','',400));
    ({url:targetUrl, parsed:parsedUrl} = normaliseUrl(raw));
  } catch(e) { return res.status(400).send(errorPage('Invalid URL: '+e.message, req.query.url, 400)); }

  if (isBlockedHost(parsedUrl.hostname))
    return res.status(403).send(errorPage('Blocked host.',targetUrl,403));

  let body, bodyContentType;
  if (req.method==='POST') {
    const ct = req.headers['content-type']||'';
    if (typeof req.body==='object'&&req.body!==null) {
      if (ct.includes('x-www-form-urlencoded')) { body=new URLSearchParams(req.body).toString(); bodyContentType='application/x-www-form-urlencoded'; }
      else { body=JSON.stringify(req.body); bodyContentType='application/json'; }
    } else if (typeof req.body==='string') { body=req.body; bodyContentType=ct; }
  }

  const fwdHeaders = {
    'User-Agent':     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':         'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language':'en-US,en;q=0.9',
    'Accept-Encoding':'gzip, deflate, br',
    'Cache-Control':  'no-cache',
    'Pragma':         'no-cache',
    'Upgrade-Insecure-Requests':'1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Referer':        parsedUrl.origin+'/',
  };
  if (bodyContentType) fwdHeaders['Content-Type']=bodyContentType;
  if (req.headers['cookie']) fwdHeaders['Cookie']=req.headers['cookie'];

  const ac=new AbortController();
  const timer=setTimeout(()=>ac.abort(),15_000);

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method==='POST'?'POST':'GET',
      headers: fwdHeaders, body, redirect:'follow', signal:ac.signal,
    });
    clearTimeout(timer);

    for (const [k,v] of upstream.headers) {
      const kl=k.toLowerCase();
      if (STRIP_HEADERS.has(kl)) continue;
      if (kl==='set-cookie') { res.setHeader('Set-Cookie',v); continue; }
      if (['etag','last-modified','cache-control','expires'].includes(kl)) res.setHeader(k,v);
    }
    applyCorsHeaders(res);

    const serverCT   = upstream.headers.get('content-type')||'';
    const enc        = upstream.headers.get('content-encoding')||'';
    const effectiveCT= guessTypeFromUrl(targetUrl, serverCT);

    // ── HTML ────────────────────────────────────────────────────────────────
    if (effectiveCT.includes('text/html')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      let html  = (await decompress(raw,enc)).toString('utf8');
      const base= targetUrl;

      for (const [tag,attr] of [
        ['img','src'],['script','src'],['link','href'],
        ['video','src'],['audio','src'],['source','src'],
        ['input','src'],['iframe','src'],['track','src'],
        ['embed','src'],['object','data'],['video','poster'],
        ['img','data-src'],['img','data-lazy-src'],['img','data-original'],
        ['div','data-bg'],['section','data-bg'],['body','background'],
      ]) html = rewriteAttr(html, tag, attr, base, reqOrigin);

      html = rewriteSrcset(html, base, reqOrigin);

      html = html.replace(/(<form(?:\s[^>]*)?)\saction=(["'])([^"']+)\2/gi, (_m,pre,q,url) => {
        const p=proxyUrl(url,base,reqOrigin); return p?`${pre} action=${q}${p}${q}`:_m;
      });
      html = html.replace(/(\sstyle=)(["'])([^"']*)\2/gi, (_m,pre,q,s) =>
        `${pre}${q}${rewriteCssUrls(s,base,reqOrigin)}${q}`
      );
      html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
        (_m,open,css,close) => open+rewriteCssUrls(css,base,reqOrigin)+close
      );
      html = html
        .replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*\/?>/gi,'')
        .replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*\/?>/gi,'')
        .replace(/<meta[^>]*name=["']referrer["'][^>]*\/?>/gi,'');

      const rwScript= buildRewriterScript(targetUrl, reqOrigin);
      const hasBase = /<base\s[^>]*href/i.test(html);
      const baseTag = hasBase?'': `<base href="${targetUrl}">`;

      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/(<head[^>]*>)/i, `$1${baseTag}`);
        // Inject rewriter as FIRST thing — before any other script
        if (/<script/i.test(html)) html=html.replace(/(<script)/i, rwScript+'$1');
        else html=html.replace(/(<\/head>)/i, rwScript+'$1');
      } else {
        html = baseTag+rwScript+html;
      }

      res.setHeader('Content-Type','text/html; charset=utf-8');
      return res.status(upstream.status).send(html);
    }

    // ── CSS — use CSS file's own URL as base ─────────────────────────────────
    if (effectiveCT.includes('text/css')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const css = rewriteCssUrls((await decompress(raw,enc)).toString('utf8'), targetUrl, reqOrigin);
      res.setHeader('Content-Type','text/css; charset=utf-8');
      return res.status(upstream.status).send(css);
    }

    // ── JavaScript ────────────────────────────────────────────────────────────
    if (effectiveCT.includes('javascript')||effectiveCT.includes('ecmascript')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const js  = (await decompress(raw,enc)).toString('utf8')
        .replace(/((?:window\.)?location\.(?:href|assign|replace)\s*=\s*)(["'])([^"']+)\2/g,
          (_m,pre,q,url) => { const p=proxyUrl(url,targetUrl,reqOrigin); return p?`${pre}${q}${p}${q}`:_m; });
      res.setHeader('Content-Type', effectiveCT.includes(';')?effectiveCT:effectiveCT+'; charset=utf-8');
      return res.status(upstream.status).send(js);
    }

    // ── Binary pass-through ───────────────────────────────────────────────────
    res.setHeader('Content-Type', serverCT||'application/octet-stream');
    return res.status(upstream.status).send(Buffer.from(await upstream.arrayBuffer()));

  } catch(err) {
    clearTimeout(timer);
    const timeout = err.name==='AbortError';
    return res.status(timeout?504:502).send(errorPage(
      timeout ? 'Target server did not respond within 15 seconds.' : err.message,
      targetUrl, timeout?504:502
    ));
  }
};
