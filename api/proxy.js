/**
 * CycloneX Proxy — api/proxy.js (v3)
 *
 * Key fixes over v2:
 *  - CSS rewriter uses the CSS file's own URL as base (not the page URL)
 *  - Robust attribute rewriter handles complex/multi-attribute tags
 *  - Rewrites ALL link[href] (preload, prefetch, icon, stylesheet, etc.)
 *  - Injected rewriter patches document.createElement to intercept dynamic
 *    <link>, <style>, <script> injection by JS frameworks (React/Vue/Next)
 *  - applyCorsHeaders() on every response type so fonts/images never CORS-block
 *  - Handles content-type mismatches (CSS/JS served as octet-stream)
 *  - @import without quotes handled
 *  - Timeout raised to 15s
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
  if (!b || now > b.resetAt) {
    b = { count: 1, resetAt: now + RATE_WINDOW_MS };
    rateBuckets.set(ip, b);
    return false;
  }
  b.count++;
  return b.count > RATE_MAX;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k);
}, 30_000).unref();

// ── SSRF blocklist ────────────────────────────────────────────────────────────
const BLOCKED_HOSTS = new Set([
  'localhost','127.0.0.1','0.0.0.0','::1',
  'metadata.google.internal','169.254.169.254',
]);
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h)) return true;
  const parts = h.split('.');
  if (parts[0] === '10') return true;
  if (parts[0] === '192' && parts[1] === '168') return true;
  if (parts[0] === '172') { const n = parseInt(parts[1], 10); if (n >= 16 && n <= 31) return true; }
  return false;
}

// ── URL helpers ───────────────────────────────────────────────────────────────
function normaliseUrl(raw) {
  let u = raw.trim();
  try { u = decodeURIComponent(u); } catch (_) {}
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  const parsed = new URL(u);
  return { url: parsed.href, parsed };
}

// ── Decompression ─────────────────────────────────────────────────────────────
async function decompress(buf, encoding) {
  const enc = (encoding || '').toLowerCase().trim();
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return await gunzip(buf);
    if (enc === 'deflate')                  return await inflateRaw(buf);
    if (enc === 'br')                       return await brotliDecompress(buf);
  } catch (_) {}
  return buf;
}

// ── Proxy URL builder ─────────────────────────────────────────────────────────
const PROXY_PATH = '/api/proxy?url=';

function proxyUrl(url, base) {
  if (!url) return null;
  const s = url.trim();
  if (!s) return null;
  if (/^(data:|javascript:|blob:|about:|#|mailto:|tel:)/i.test(s)) return null;
  try {
    const abs = new URL(s, base).href;
    return PROXY_PATH + encodeURIComponent(abs);
  } catch (_) { return null; }
}

// ── Robust attribute rewriter ─────────────────────────────────────────────────
function rewriteAttr(html, tag, attr, base) {
  const tagRe = new RegExp(`(<${tag}(?:\\s[^>]*)?)\\s${attr}=(["'])([^"']*?)\\2`, 'gi');
  return html.replace(tagRe, (m, pre, q, url) => {
    const p = proxyUrl(url, base);
    return p ? `${pre} ${attr}=${q}${p}${q}` : m;
  });
}

// ── srcset rewriter ───────────────────────────────────────────────────────────
function rewriteSrcset(html, base) {
  return html.replace(/(\ssrcset=)(["'])([^"']+)(\2)/gi, (_m, pre, q, val, qc) => {
    const rewritten = val.replace(/([^\s,][^\s,]*?)(\s+[\d.]+[wx])?(?=\s*,|\s*$)/g, (part, url, desc) => {
      if (!url) return part;
      const p = proxyUrl(url.trim(), base);
      return p ? (p + (desc || '')) : part;
    });
    return `${pre}${q}${rewritten}${qc}`;
  });
}

// ── CSS url() / @import rewriter ─────────────────────────────────────────────
// IMPORTANT: cssFileUrl must be the URL of the CSS file itself, not the page
function rewriteCssUrls(css, cssFileUrl) {
  return css
    .replace(/url\(\s*(["']?)([^)"'\s]+)\1\s*\)/gi, (_m, q, url) => {
      const p = proxyUrl(url, cssFileUrl);
      return p ? `url('${p}')` : _m;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (_m, _q, url) => {
      const p = proxyUrl(url, cssFileUrl);
      return p ? `@import '${p}'` : _m;
    })
    .replace(/@import\s+url\(\s*(["']?)([^)"'\s]+)\1\s*\)/gi, (_m, _q, url) => {
      const p = proxyUrl(url, cssFileUrl);
      return p ? `@import url('${p}')` : _m;
    });
}

// ── Strip these headers from upstream responses ───────────────────────────────
const STRIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'x-frame-options','x-content-type-options','strict-transport-security',
  'permissions-policy','cross-origin-embedder-policy',
  'cross-origin-opener-policy','cross-origin-resource-policy',
  'report-to','nel','expect-ct','content-encoding',
  'x-xss-protection','referrer-policy','origin-agent-cluster',
  'document-policy','feature-policy','timing-allow-origin',
]);

// ── Apply CORS + framing headers to every response ────────────────────────────
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

// ── Guess real content type when server sends wrong one ──────────────────────
function guessType(url, serverType) {
  if (serverType && !serverType.includes('octet-stream') && !serverType.includes('plain')) return serverType;
  const u = url.split('?')[0].toLowerCase();
  if (u.endsWith('.css'))              return 'text/css';
  if (u.endsWith('.js') || u.endsWith('.mjs')) return 'application/javascript';
  if (u.endsWith('.html') || u.endsWith('.htm')) return 'text/html';
  if (u.endsWith('.json'))             return 'application/json';
  if (u.endsWith('.svg'))              return 'image/svg+xml';
  return serverType || 'application/octet-stream';
}

// ── Rewriter script injected into every HTML page ─────────────────────────────
function buildRewriterScript(targetUrl, origin) {
  const safe = (s) => s.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  return `<script data-cx-rewriter>
(function(){
  var PROXY='${PROXY_PATH}',PAGE_URL='${safe(targetUrl)}',PAGE_ORIGIN='${safe(origin)}';

  function toAbs(h){
    if(!h||typeof h!=='string')return null;
    h=h.trim();
    if(/^(javascript:|#|data:|mailto:|tel:|blob:|about:)/i.test(h))return null;
    try{return new URL(h,PAGE_URL).href;}catch(e){return null;}
  }
  function proxify(url){var a=toAbs(url);return a?PROXY+encodeURIComponent(a):null;}

  // <a> clicks
  document.addEventListener('click',function(e){
    var el=e.target.closest('a[href]');if(!el)return;
    var href=el.getAttribute('href');
    if(!href||/^(javascript:|#|mailto:|tel:)/i.test(href))return;
    var a=toAbs(href);if(!a)return;
    e.preventDefault();e.stopPropagation();
    window.parent.postMessage({type:'cx-navigate',url:a},'*');
  },true);

  // <form> submits
  document.addEventListener('submit',function(e){
    var form=e.target;if(!form||form.tagName!=='FORM')return;
    e.preventDefault();e.stopPropagation();
    var action=form.getAttribute('action')||PAGE_URL;
    var method=(form.getAttribute('method')||'GET').toUpperCase();
    var a=toAbs(action)||PAGE_URL;
    var params=new URLSearchParams(new FormData(form));
    if(method==='GET'){window.parent.postMessage({type:'cx-navigate',url:a.split('?')[0]+'?'+params},'*');}
    else{window.parent.postMessage({type:'cx-navigate',url:a,method:'POST',body:params.toString()},'*');}
  },true);

  // history
  ['pushState','replaceState'].forEach(function(fn){
    var orig=history[fn].bind(history);
    history[fn]=function(state,title,url){
      if(!url){try{orig(state,title,url);}catch(e){}return;}
      var a=toAbs(String(url));
      if(a){try{orig(state,title,PROXY+encodeURIComponent(a));}catch(e){window.parent.postMessage({type:'cx-navigate',url:a},'*');}}
      else{try{orig(state,title,url);}catch(e){}}
    };
  });

  // fetch
  var _fetch=window.fetch.bind(window);
  window.fetch=function(input,init){
    var url=typeof input==='string'?input:(input&&input.url)?input.url:'';
    var a=toAbs(url);
    if(a&&!a.startsWith(location.origin)){input=PROXY+encodeURIComponent(a);init=Object.assign({},init||{},{credentials:'omit',mode:'cors'});}
    return _fetch(input,init);
  };

  // XHR
  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(method,url,async,user,pass){
    var a=toAbs(url);
    if(a&&!a.startsWith(location.origin))url=PROXY+encodeURIComponent(a);
    return _open.call(this,method,url,async!==false,user,pass);
  };

  // Intercept dynamic element creation (React/Vue/Angular inject <link>/<script>)
  var _ce=document.createElement.bind(document);
  document.createElement=function(tag){
    var el=_ce(tag);
    var t=(tag||'').toLowerCase();
    function patchProp(proto,prop){
      var desc=Object.getOwnPropertyDescriptor(proto,prop);
      if(!desc||!desc.set)return;
      var orig=desc.set;
      Object.defineProperty(el,prop,{
        set:function(v){var p=proxify(v);orig.call(this,p||v);},
        get:desc.get,configurable:true
      });
    }
    if(t==='link')  patchProp(HTMLLinkElement.prototype,'href');
    if(t==='script')patchProp(HTMLScriptElement.prototype,'src');
    if(t==='img')   patchProp(HTMLImageElement.prototype,'src');
    if(t==='iframe')patchProp(HTMLIFrameElement.prototype,'src');
    return el;
  };

  // MutationObserver: rewrite anything added to DOM after load
  function rewriteEl(node){
    if(node.nodeType!==1)return;
    var tag=(node.tagName||'').toLowerCase();
    ['data-src','data-lazy-src','data-original'].forEach(function(a){
      var v=node.getAttribute&&node.getAttribute(a);
      if(v){var p=proxify(v);if(p)node.setAttribute(a,p);}
    });
    if(['img','script','iframe','video','audio','source','track'].includes(tag)){
      var v=node.getAttribute('src');if(v){var p=proxify(v);if(p)node.setAttribute('src',p);}
    }
    if(tag==='link'){var v=node.getAttribute('href');if(v){var p=proxify(v);if(p)node.setAttribute('href',p);}}
    if(node.querySelectorAll){
      node.querySelectorAll('[data-src],[data-lazy-src],img[src],link[href],script[src],iframe[src]').forEach(rewriteEl);
    }
  }
  new MutationObserver(function(ms){ms.forEach(function(m){m.addedNodes.forEach(rewriteEl);});})
    .observe(document.documentElement,{childList:true,subtree:true});

  // Cookie notifications
  try{
    var _cs=Object.getOwnPropertyDescriptor(Document.prototype,'cookie').set;
    Object.defineProperty(document,'cookie',{
      set:function(v){_cs.call(document,v);try{window.parent.postMessage({type:'cx-cookie',cookie:v,origin:PAGE_ORIGIN},'*');}catch(_){}},
      get:Object.getOwnPropertyDescriptor(Document.prototype,'cookie').get,configurable:true
    });
  }catch(_){}

  window.addEventListener('message',function(e){
    if(e.data&&e.data.type==='cx-scroll-to'){try{window.scrollTo(e.data.x||0,e.data.y||0);}catch(_){}}
  });
})();
<\/script>`;
}

// ── Error page ────────────────────────────────────────────────────────────────
function errorPage(msg, target, status) {
  const safeMsg=String(msg).replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const safeTarget=String(target||'').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const jsTarget=String(target||'').replace(/'/g,"\\'");
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Proxy Error</title>
<style>*{box-sizing:border-box}body{margin:0;font-family:'Courier New',monospace;background:#080808;color:#ff6060;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#111;border:1px solid #2a2a2a;border-radius:14px;padding:40px 44px;max-width:540px;width:92%}h2{margin:0 0 20px;font-size:18px;color:#ff8585}.label{color:#555;font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin-top:20px}.code{background:#1a1a1a;border:1px solid #222;border-radius:7px;padding:12px 14px;margin-top:6px;color:#fc9;font-size:12px;word-break:break-all;line-height:1.6}button{margin-top:24px;background:linear-gradient(135deg,#1e90ff,#0070d0);color:#fff;border:none;border-radius:9px;padding:11px 22px;cursor:pointer;font-size:13px;transition:opacity .15s}button:hover{opacity:.85}.status{display:inline-block;background:#ff3030;color:#fff;border-radius:5px;padding:2px 9px;font-size:11px;margin-bottom:10px}</style></head><body>
<div class="card"><div class="status">${status}</div><h2>⚡ Proxy Error</h2><div class="label">What happened</div><div class="code">${safeMsg}</div><div class="label">Target URL</div><div class="code">${safeTarget}</div>${target?`<button onclick="window.parent.postMessage({type:'cx-navigate',url:'${jsTarget}'},'*')">↩ Retry</button>`:''}</div></body></html>`;
}

// ── Main handler ──────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(ip)) return res.status(429).send(errorPage('Too many requests.','',429));

  let targetUrl, parsedUrl;
  try {
    const raw = req.query.url || '';
    if (!raw) return res.status(400).send(errorPage('Missing ?url= parameter.','',400));
    ({ url: targetUrl, parsed: parsedUrl } = normaliseUrl(raw));
  } catch (e) {
    return res.status(400).send(errorPage('Invalid URL: '+e.message, req.query.url, 400));
  }

  if (isBlockedHost(parsedUrl.hostname))
    return res.status(403).send(errorPage('Access to this host is blocked.', targetUrl, 403));

  let body, bodyContentType;
  if (req.method === 'POST') {
    const ct = req.headers['content-type'] || '';
    if (typeof req.body === 'object' && req.body !== null) {
      if (ct.includes('application/x-www-form-urlencoded')) { body=new URLSearchParams(req.body).toString(); bodyContentType='application/x-www-form-urlencoded'; }
      else { body=JSON.stringify(req.body); bodyContentType='application/json'; }
    } else if (typeof req.body === 'string') { body=req.body; bodyContentType=ct; }
  }

  const forwardHeaders = {
    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control':   'no-cache',
    'Pragma':          'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest':  'document',
    'Sec-Fetch-Mode':  'navigate',
    'Sec-Fetch-Site':  'none',
    'Referer':         parsedUrl.origin + '/',
  };
  if (bodyContentType) forwardHeaders['Content-Type'] = bodyContentType;
  if (req.headers['cookie']) forwardHeaders['Cookie'] = req.headers['cookie'];

  const ac    = new AbortController();
  const timer = setTimeout(() => ac.abort(), 15_000);

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method === 'POST' ? 'POST' : 'GET',
      headers: forwardHeaders, body, redirect: 'follow', signal: ac.signal,
    });
    clearTimeout(timer);

    for (const [k, v] of upstream.headers) {
      const kl = k.toLowerCase();
      if (STRIP_HEADERS.has(kl)) continue;
      if (kl === 'set-cookie') { res.setHeader('Set-Cookie', v); continue; }
      if (['etag','last-modified','cache-control','expires'].includes(kl)) res.setHeader(k, v);
    }

    applyCorsHeaders(res);

    const serverCT    = upstream.headers.get('content-type') || '';
    const enc         = upstream.headers.get('content-encoding') || '';
    const effectiveCT = guessType(targetUrl, serverCT);

    // ── HTML ────────────────────────────────────────────────────────────────
    if (effectiveCT.includes('text/html')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      let html  = (await decompress(raw, enc)).toString('utf8');
      const base = targetUrl;

      for (const [tag, attr] of [
        ['img','src'],['script','src'],['link','href'],
        ['video','src'],['audio','src'],['source','src'],
        ['input','src'],['iframe','src'],['track','src'],
        ['embed','src'],['object','data'],['video','poster'],
        ['img','data-src'],['img','data-lazy-src'],['img','data-original'],
        ['div','data-bg'],['section','data-bg'],['body','background'],
      ]) html = rewriteAttr(html, tag, attr, base);

      html = rewriteSrcset(html, base);

      html = html.replace(/(<form(?:\s[^>]*)?)\saction=(["'])([^"']+)\2/gi, (_m, pre, q, url) => {
        const p = proxyUrl(url, base); return p ? `${pre} action=${q}${p}${q}` : _m;
      });

      html = html.replace(/(\sstyle=)(["'])([^"']*)\2/gi, (_m, pre, q, s) =>
        `${pre}${q}${rewriteCssUrls(s, base)}${q}`
      );

      html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
        (_m, open, css, close) => open + rewriteCssUrls(css, base) + close
      );

      html = html
        .replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*\/?>/gi, '')
        .replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*\/?>/gi, '')
        .replace(/<meta[^>]*name=["']referrer["'][^>]*\/?>/gi, '');

      const rewriterScript = buildRewriterScript(targetUrl, parsedUrl.origin);
      const hasBase = /<base\s[^>]*href/i.test(html);
      const baseTag = hasBase ? '' : `<base href="${targetUrl}">`;

      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/(<head[^>]*>)/i, `$1${baseTag}`);
        if (/<script/i.test(html)) html = html.replace(/(<script)/i, rewriterScript+'$1');
        else html = html.replace(/(<\/head>)/i, rewriterScript+'$1');
      } else {
        html = baseTag + rewriterScript + html;
      }

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(upstream.status).send(html);
    }

    // ── CSS — use the CSS file's OWN URL as base for relative resources ───
    if (effectiveCT.includes('text/css')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const css = rewriteCssUrls((await decompress(raw, enc)).toString('utf8'), targetUrl);
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
      return res.status(upstream.status).send(css);
    }

    // ── JavaScript ──────────────────────────────────────────────────────────
    if (effectiveCT.includes('javascript') || effectiveCT.includes('ecmascript')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const js = (await decompress(raw, enc)).toString('utf8')
        .replace(/((?:window\.)?location\.(?:href|assign|replace)\s*=\s*)(["'])([^"']+)\2/g,
          (_m, pre, q, url) => { const p=proxyUrl(url,targetUrl); return p?`${pre}${q}${p}${q}`:_m; });
      res.setHeader('Content-Type', effectiveCT.includes(';') ? effectiveCT : effectiveCT+'; charset=utf-8');
      return res.status(upstream.status).send(js);
    }

    // ── Binary pass-through ─────────────────────────────────────────────────
    res.setHeader('Content-Type', serverCT || 'application/octet-stream');
    const buf = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(buf));

  } catch (err) {
    clearTimeout(timer);
    const timeout = err.name === 'AbortError';
    const status  = timeout ? 504 : 502;
    const msg     = timeout ? 'The target server did not respond within 15 seconds.' : err.message;
    return res.status(status).send(errorPage(msg, targetUrl, status));
  }
};
