/**
 * CycloneX Proxy — api/proxy.js (v8)
 *
 * Fixes over v5:
 *  1. data: URI rewriting bug — rewriter was prepending proxy URL to data: URIs
 *  2. Relative URL base resolution bug — DuckDuckGo /ac/ autocomplete was resolving
 *     against Vercel origin instead of DuckDuckGo origin
 *  3. chrome-extension:// URLs no longer attempted to proxy (were causing 502s)
 *  4. Double-proxy prevention tightened — handles already-proxied URLs in navigation
 *  5. history.replaceState patch strengthened — catches URL format YouTube uses
 *  6. vercel.json body parser enabled for POST with raw buffer pass-through
 *  7. DuckDuckGo search suggestions proxied correctly via /ac/ route
 *  8. Browser extension content script URLs (chrome-extension://, moz-extension://) blocked from proxy
 */

'use strict';

const { promisify } = require('util');
const zlib = require('zlib');

const gunzip           = promisify(zlib.gunzip);
const inflateRaw       = promisify(zlib.inflateRaw);
const brotliDecompress = promisify(zlib.brotliDecompress);

// ── Rate limiter ──────────────────────────────────────────────────────────────
const RATE_WINDOW_MS = 10_000;
const RATE_MAX       = 200;
const rateBuckets    = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) { b = { count: 1, resetAt: now + RATE_WINDOW_MS }; rateBuckets.set(ip, b); return false; }
  b.count++;
  return b.count > RATE_MAX;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k); }, 30_000).unref();

// ── SSRF / extension blocklist ────────────────────────────────────────────────
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
  // Block browser extension URLs from being proxied
  if (/^(chrome-extension|moz-extension|safari-extension|ms-browser-extension):\/\//i.test(u)) {
    throw new Error('Browser extension URLs cannot be proxied.');
  }
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

function isAlreadyProxied(url, origin) {
  if (!url) return false;
  // Already wrapped: /api/proxy?url= at Vercel origin OR relative proxy path
  if (origin && url.startsWith(origin + PROXY_PATH)) return true;
  if (url.startsWith(PROXY_PATH)) return true;
  return false;
}

function proxyUrl(url, base, origin) {
  if (!url) return null;
  const s = url.trim();
  // Never touch these schemes
  if (/^(data:|javascript:|blob:|about:|#|mailto:|tel:|chrome-extension:|moz-extension:|safari-extension:)/i.test(s)) return null;
  try {
    const resolved = new URL(s, base).href;
    // Never re-proxy
    if (isAlreadyProxied(resolved, origin)) return null;
    // Never proxy our own app origin
    if (origin && resolved.startsWith(origin + '/') && !resolved.includes(PROXY_PATH)) return null;
    const prefix = origin ? origin + PROXY_PATH : PROXY_PATH;
    return prefix + encodeURIComponent(resolved);
  } catch(_) { return null; }
}

// ── Attribute rewriter ────────────────────────────────────────────────────────
function rewriteAttr(html, tag, attr, base, origin) {
  const re = new RegExp(`(<${tag}(?:\\s[^>]*)?)\\s${attr}=([\"'])([^\"']*?)\\2`, 'gi');
  return html.replace(re, (m, pre, q, url) => {
    const trimmed = url.trim();
    // Never touch data URIs, blob URIs, or already-proxied URLs
    if (/^(data:|blob:|javascript:)/i.test(trimmed)) return m;
    if (trimmed.includes('/api/proxy?url=')) return m;
    const p = proxyUrl(url, base, origin);
    return p ? `${pre} ${attr}=${q}${p}${q}` : m;
  });
}

function rewriteSrcset(html, base, origin) {
  return html.replace(/(\ssrcset=)([\"'])([^\"']+)(\2)/gi, (_m, pre, q, val, qc) => {
    // Split on commas that are NOT inside a data: URI.
    // A data: URI looks like: data:<type>[;base64],<payload>
    // We detect entry boundaries by splitting only on ", " or "," that are
    // followed by an optional space then a non-base64-garbage token.
    // Simpler robust approach: parse candidates manually.
    const candidates = [];
    let rest = val.trim();
    while (rest.length) {
      // A data: entry — consume until next whitespace-delimited descriptor or end
      if (/^data:/i.test(rest)) {
        // find the boundary: optional descriptor (digits+w/x) then comma or end
        const m = rest.match(/^(data:[^\s,]+,[^\s,]*(?:\s+[\d.]+[wx])?)(\s*,\s*|$)/i);
        if (m) { candidates.push(m[1]); rest = rest.slice(m[0].length).trimStart(); continue; }
        // fallback: take everything
        candidates.push(rest); break;
      }
      // Normal URL entry: url optionally followed by descriptor
      const m = rest.match(/^([^\s,]+(?:\s+[\d.]+[wx])?)(\s*,\s*|$)/);
      if (m) { candidates.push(m[1]); rest = rest.slice(m[0].length).trimStart(); continue; }
      candidates.push(rest); break;
    }
    const rw = candidates.map(entry => {
      const [url, ...descParts] = entry.split(/\s+/);
      const desc = descParts.length ? ' ' + descParts.join(' ') : '';
      if (!url || /^data:/i.test(url.trim())) return entry;
      const p = proxyUrl(url.trim(), base, origin);
      return p ? (p + desc) : entry;
    }).join(', ');
    return `${pre}${q}${rw}${qc}`;
  });
}

// ── CSS rewriter ──────────────────────────────────────────────────────────────
function rewriteCssUrls(css, cssBase, origin) {
  return css
    .replace(/url\(\s*([\"']?)([^)"'\s]+)\1\s*\)/gi, (_m, q, url) => {
      if (/^data:/i.test(url.trim())) return _m;
      const p = proxyUrl(url, cssBase, origin); return p ? `url('${p}')` : _m;
    })
    .replace(/@import\s+(['\"])([^'"]+)\1/gi, (_m, _q, url) => {
      const p = proxyUrl(url, cssBase, origin); return p ? `@import '${p}'` : _m;
    })
    .replace(/@import\s+url\(\s*([\"']?)([^)"'\s]+)\1\s*\)/gi, (_m, _q, url) => {
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
  res.setHeader('Access-Control-Allow-Methods',     'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers',     '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Cross-Origin-Resource-Policy',     'cross-origin');
  res.setHeader('Cross-Origin-Embedder-Policy',     'unsafe-none');
  res.setHeader('Cross-Origin-Opener-Policy',       'unsafe-none');
  res.setHeader('X-Frame-Options',                  'ALLOWALL');
  res.setHeader('Content-Security-Policy',          '');
}

function guessTypeFromUrl(url, serverType) {
  if (serverType && !serverType.includes('octet-stream') && !serverType.includes('plain')) return serverType;
  const u = url.split('?')[0].toLowerCase();
  if (u.endsWith('.css'))                    return 'text/css';
  if (u.endsWith('.js')||u.endsWith('.mjs')) return 'application/javascript';
  if (u.endsWith('.html')||u.endsWith('.htm')) return 'text/html';
  if (u.endsWith('.json'))                   return 'application/json';
  if (u.endsWith('.svg'))                    return 'image/svg+xml';
  return serverType || 'application/octet-stream';
}

// ── Partial support sites ─────────────────────────────────────────────────────
const PARTIAL_SUPPORT_HOSTS = [
  'youtube.com','www.youtube.com',
  'twitter.com','x.com','www.x.com',
  'facebook.com','www.facebook.com',
  'instagram.com','www.instagram.com',
  'netflix.com','www.netflix.com',
  'tiktok.com','www.tiktok.com',
  'twitch.tv','www.twitch.tv',
  'discord.com','www.discord.com',
  'spotify.com','open.spotify.com',
  'reddit.com','www.reddit.com',
  'linkedin.com','www.linkedin.com',
];
function isPartialSupport(hostname) {
  return PARTIAL_SUPPORT_HOSTS.some(h => hostname === h || hostname.endsWith('.' + h));
}

function buildWarningBanner(hostname) {
  const h = hostname.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return `<div id="cx-partial-warn" style="position:fixed;bottom:0;left:0;right:0;z-index:2147483647;background:rgba(18,18,18,0.96);border-top:1px solid rgba(252,211,77,0.3);backdrop-filter:blur(16px);font-family:-apple-system,BlinkMacSystemFont,monospace;font-size:12px;color:#fcd34d;display:flex;align-items:center;gap:10px;padding:9px 16px;box-shadow:0 -6px 28px rgba(0,0,0,0.6);">
  <span style="font-size:16px;flex-shrink:0">⚠️</span>
  <span><strong style="color:#fde68a">${h}</strong> may have limited functionality through the proxy — login, video playback, and live features may not fully work.</span>
  <button onclick="document.getElementById('cx-partial-warn').remove()" style="margin-left:auto;background:none;border:1px solid rgba(252,211,77,0.35);color:#fcd34d;font-family:inherit;font-size:11px;padding:4px 11px;border-radius:6px;cursor:pointer;flex-shrink:0;white-space:nowrap;">Dismiss ✕</button>
</div>`;
}

// ── Client-side rewriter script ───────────────────────────────────────────────
function buildRewriterScript(targetUrl, origin) {
  const safe = s => s.replace(/\\/g,'\\\\').replace(/`/g,'\\`').replace(/'/g,"\\'").replace(/<\//g,'<\\/');
  const targetOrigin = (() => { try { return new URL(targetUrl).origin; } catch(_) { return ''; } })();

  return `<script data-cx-rewriter>
(function(){
'use strict';
var PROXY='${safe(origin)}${PROXY_PATH}',PAGE_URL='${safe(targetUrl)}',PAGE_ORIGIN='${safe(targetOrigin)}';

// ── Skip schemes that should never be proxied ─────────────────────────────────
var SKIP_RE=/^(data:|javascript:|blob:|about:|#|mailto:|tel:|chrome-extension:|moz-extension:|safari-extension:)/i;

function toAbs(h){
  if(!h||typeof h!=='string')return null;
  h=h.trim();
  if(SKIP_RE.test(h))return null;
  try{return new URL(h,PAGE_URL).href;}catch(e){return null;}
}

function px(url){
  if(!url)return null;
  var s=String(url).trim();
  // Never proxy data URIs or extension URLs
  if(SKIP_RE.test(s))return null;
  var a=toAbs(s);
  if(!a)return null;
  // Never double-proxy
  if(a.indexOf(PROXY)!==-1&&a.indexOf('?url=')!==-1)return null;
  // Never proxy our own Vercel app pages (only proxy external URLs)
  var appOrigin='${safe(origin)}';
  if(a.startsWith(appOrigin+'/api/proxy'))return null;
  return PROXY+encodeURIComponent(a);
}

// ── Spoof window.location so sites think they're running on their own origin ──
(function(){
  if(!PAGE_ORIGIN)return;
  try{
    var tURL=new URL(PAGE_URL);
    var props={
      href:PAGE_URL,origin:tURL.origin,protocol:tURL.protocol,
      host:tURL.host,hostname:tURL.hostname,port:tURL.port,
      pathname:tURL.pathname,search:tURL.search,hash:tURL.hash
    };
    Object.keys(props).forEach(function(k){
      try{Object.defineProperty(window.location,k,{get:function(){return props[k];},configurable:true});}catch(e){}
    });
    try{window.location.assign=function(u){window.parent.postMessage({type:'cx-navigate',url:toAbs(u)||u},'*');};}catch(e){}
    try{window.location.replace=function(u){window.parent.postMessage({type:'cx-navigate',url:toAbs(u)||u},'*');};}catch(e){}
  }catch(e){}
})();

// ── history: patch BEFORE any site JS ────────────────────────────────────────
// Sites call replaceState/pushState with their own-origin absolute URLs.
// Translating them to an absolute proxy URL (https://vercel.app/api/proxy?url=https://google.com/...)
// triggers a SecurityError because the history URL must share the document origin.
// Fix: translate to a RELATIVE proxy path (/api/proxy?url=...) instead.
// ALSO: some URLs may already contain /api/proxy?url= (from server rewriting) — skip those.
(function(){
  var appOrigin='${safe(origin)}';
  ['pushState','replaceState'].forEach(function(fn){
    var orig=history[fn].bind(history);
    history[fn]=function(state,title,url){
      if(!url){try{orig(state,title,url);}catch(e){}return;}
      var u=String(url);
      // Already a relative path or fragment — pass through unchanged
      if(!u.startsWith('http')){{try{orig(state,title,u);}catch(e){}return;}}
      // Already on our Vercel origin — pass through unchanged
      if(u.startsWith(appOrigin)){try{orig(state,title,u);}catch(e){}return;}
      // Contains /api/proxy?url= anywhere (e.g. google.com/api/proxy?url=...) — strip to just the proxied path
      var pidx=u.indexOf('/api/proxy?url=');
      if(pidx!==-1){
        // Extract the relative proxy path portion and use it
        try{orig(state,title,u.slice(pidx));}catch(e){}
        return;
      }
      // Absolute URL with foreign origin -> translate to RELATIVE proxy path (avoids SecurityError)
      try{orig(state,title,'/api/proxy?url='+encodeURIComponent(u));}catch(e){}
    };
  });
})();

var SRC_ATTRS={src:1,href:1,action:1,poster:1,'data-src':1,'data-lazy-src':1,'data-original':1};
var SRC_TAGS={img:1,script:1,link:1,iframe:1,video:1,audio:1,source:1,track:1,embed:1,object:1,form:1};

// ── Patch setAttribute ────────────────────────────────────────────────────────
var _setAttr=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(name,value){
  var n=name&&name.toLowerCase();
  var t=this.tagName&&this.tagName.toLowerCase();
  if(value&&typeof value==='string'&&!SKIP_RE.test(value.trim())&&SRC_ATTRS[n]&&(SRC_TAGS[t]||n==='href'||n==='src')){
    var p=px(value);if(p){_setAttr.call(this,name,p);return;}
  }
  _setAttr.call(this,name,value);
};

// ── Patch property setters ────────────────────────────────────────────────────
function patchProto(proto,prop){
  var desc=Object.getOwnPropertyDescriptor(proto,prop);
  if(!desc||!desc.set)return;
  var origSet=desc.set,origGet=desc.get;
  Object.defineProperty(proto,prop,{
    set:function(v){
      var vs=String(v||'').trim();
      if(SKIP_RE.test(vs)){origSet.call(this,v);return;}
      var p=px(v);origSet.call(this,p||v);
    },get:origGet,configurable:true
  });
}
patchProto(HTMLScriptElement.prototype,'src');
patchProto(HTMLImageElement.prototype,'src');
patchProto(HTMLIFrameElement.prototype,'src');
patchProto(HTMLLinkElement.prototype,'href');
patchProto(HTMLSourceElement.prototype,'src');

// ── insertAdjacentHTML + innerHTML ────────────────────────────────────────────
var _iah=Element.prototype.insertAdjacentHTML;
Element.prototype.insertAdjacentHTML=function(pos,html){_iah.call(this,pos,rwSnippet(html));};
var _inHTMLDesc=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');
if(_inHTMLDesc&&_inHTMLDesc.set){
  var _inSet=_inHTMLDesc.set;
  Object.defineProperty(Element.prototype,'innerHTML',{
    set:function(v){_inSet.call(this,rwSnippet(v));},get:_inHTMLDesc.get,configurable:true
  });
}

function rwSnippet(html){
  if(!html||typeof html!=='string')return html;
  function rwQ(h,q){
    return h.replace(new RegExp('([\\s(](?:src|href|action)=)('+q+')([^'+q+']+)'+q,'gi'),
      function(m,pre,qq,url){
        if(SKIP_RE.test(url.trim()))return m;
        var p=px(url);return p?pre+qq+p+qq:m;
      });
  }
  return rwQ(rwQ(html,'"'),"'");
}

// ── fetch ─────────────────────────────────────────────────────────────────────
var _fetch=window.fetch.bind(window);
window.fetch=function(input,init){
  var url=typeof input==='string'?input:(input&&input.url?input.url:'');
  if(!url)return _fetch(input,init);
  // Skip data/blob/extension URLs
  if(SKIP_RE.test(url.trim()))return _fetch(input,init);
  // Already proxied
  if(url.indexOf(PROXY)!==-1&&url.indexOf('?url=')!==-1)return _fetch(input,init);

  var a=toAbs(url);
  if(!a)return _fetch(input,init);

  var newInit=Object.assign({},init||{},{credentials:'omit',mode:'cors'});
  if(!/^https?:\/\//i.test(url)&&!url.startsWith('//')){
    // Relative — resolve against PAGE_URL (the proxied site's origin, not Vercel)
    var resolved;
    try{resolved=new URL(url,PAGE_URL).href;}catch(_){return _fetch(input,init);}
    // Only proxy if it's not our own app
    if(resolved.startsWith('${safe(origin)}/api/proxy')||resolved.startsWith('${safe(origin)}/api/search')){
      return _fetch(input,init);
    }
    input=PROXY+encodeURIComponent(resolved);
  } else {
    // Absolute URL — proxy ALL foreign URLs regardless of location.origin
    // (location.origin may equal Vercel origin due to allow-same-origin sandbox)
    var isOwnApp=a.startsWith('${safe(origin)}/api/proxy')||a.startsWith('${safe(origin)}/api/search');
    if(isOwnApp)return _fetch(input,init);
    input=PROXY+encodeURIComponent(a);
  }
  return _fetch(input,newInit);
};

// ── XHR ───────────────────────────────────────────────────────────────────────
var _open=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(method,url,async,user,pass){
  if(url&&typeof url==='string'&&!SKIP_RE.test(url.trim())){
    if(url.indexOf(PROXY)!==-1&&url.indexOf('?url=')!==-1){
      // already proxied — pass through
    } else if(!/^https?:\/\//i.test(url)&&!url.startsWith('//')){
      // relative URL — resolve against the TARGET PAGE (not Vercel origin)
      try{
        var resolved=new URL(url,PAGE_URL).href;
        // Only proxy if resolved URL is not on our own app origin
        if(!resolved.startsWith('${safe(origin)}')){
          url=PROXY+encodeURIComponent(resolved);
        }
      }catch(_){}
    } else {
      var a=toAbs(url);
      // Proxy ALL absolute foreign URLs — don't rely on location.origin
      // (location.origin === Vercel origin when allow-same-origin is set,
      //  which would incorrectly skip Google/DuckDuckGo XHRs)
      if(a){
        var isOwnAppUrl=a.startsWith('${safe(origin)}/api/proxy')||a.startsWith('${safe(origin)}/api/search');
        if(!isOwnAppUrl) url=PROXY+encodeURIComponent(a);
      }
    }
  }
  return _open.call(this,method,url,async!==false,user,pass);
};

// ── Link clicks ───────────────────────────────────────────────────────────────
document.addEventListener('click',function(e){
  var el=e.target.closest('a[href]');if(!el)return;
  var href=el.getAttribute('href');
  if(!href||/^(javascript:|#|mailto:|tel:)/i.test(href))return;
  var a=toAbs(href);if(!a)return;
  e.preventDefault();e.stopPropagation();
  window.parent.postMessage({type:'cx-navigate',url:a},'*');
},true);

// ── Form submits ──────────────────────────────────────────────────────────────
document.addEventListener('submit',function(e){
  var form=e.target;if(!form||form.tagName!=='FORM')return;
  e.preventDefault();e.stopPropagation();
  var action=form.getAttribute('action')||PAGE_URL;
  var method=(form.getAttribute('method')||'GET').toUpperCase();
  var a=toAbs(action)||PAGE_URL;
  var params=new URLSearchParams(new FormData(form));
  if(method==='GET')window.parent.postMessage({type:'cx-navigate',url:a.split('?')[0]+'?'+params},'*');
  else window.parent.postMessage({type:'cx-navigate',url:a,method:'POST',body:params.toString()},'*');
},true);

// ── MutationObserver fallback ─────────────────────────────────────────────────
function rewriteNode(node){
  if(node.nodeType!==1)return;
  ['src','href','data-src','data-lazy-src','data-original'].forEach(function(attr){
    var v=node.getAttribute&&node.getAttribute(attr);
    if(!v||SKIP_RE.test(v.trim()))return;
    if(v.startsWith(PROXY))return;
    var p=px(v);if(p)_setAttr.call(node,attr,p);
  });
  if(node.querySelectorAll)node.querySelectorAll('[src],[href],[data-src],[data-lazy-src]').forEach(rewriteNode);
}
new MutationObserver(function(ms){
  ms.forEach(function(m){m.addedNodes.forEach(rewriteNode);});
}).observe(document.documentElement,{childList:true,subtree:true});

// ── Parent messages ───────────────────────────────────────────────────────────
window.addEventListener('message',function(e){
  if(e.data&&e.data.type==='cx-scroll-to'){try{window.scrollTo(e.data.x||0,e.data.y||0);}catch(_){}}
});
window.addEventListener('load',function(){
  window.parent.postMessage({type:'cx-page-loaded',url:PAGE_URL},'*');
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

// ── Raw body reader ───────────────────────────────────────────────────────────
function readRawBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error',() => resolve(Buffer.alloc(0)));
  });
}

// ── Main handler ──────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD');
  res.setHeader('Access-Control-Allow-Headers','*');
  if (req.method==='OPTIONS') return res.status(200).end();

  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  if (isRateLimited(ip)) return res.status(429).send(errorPage('Too many requests.','',429));

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
  } catch(e) {
    return res.status(400).send(errorPage(e.message, req.query.url||'', 400));
  }

  if (isBlockedHost(parsedUrl.hostname))
    return res.status(403).send(errorPage('Blocked host.',targetUrl,403));

  // ── Read raw body (works regardless of Vercel body-parser settings) ────────
  const method = req.method.toUpperCase();
  let body = null, bodyContentType = null;
  if (['POST','PUT','PATCH'].includes(method)) {
    const ct = (req.headers['content-type']||'').toLowerCase();
    // Try pre-parsed body first (Vercel JSON/form parser)
    if (req.body && typeof req.body === 'object' && !(req.body instanceof Buffer)) {
      if (ct.includes('x-www-form-urlencoded')) {
        body = new URLSearchParams(req.body).toString();
        bodyContentType = 'application/x-www-form-urlencoded';
      } else {
        body = JSON.stringify(req.body);
        bodyContentType = 'application/json';
      }
    } else if (Buffer.isBuffer(req.body) && req.body.length > 0) {
      body = req.body;
      bodyContentType = req.headers['content-type'] || 'application/octet-stream';
    } else if (typeof req.body === 'string' && req.body.length > 0) {
      body = req.body;
      bodyContentType = req.headers['content-type'] || 'text/plain';
    } else {
      // Fallback: read raw stream
      const raw = await readRawBody(req);
      if (raw.length > 0) {
        body = raw;
        bodyContentType = req.headers['content-type'] || 'application/octet-stream';
      }
    }
  }

  const isApiCall = /\/(api|youtubei|v[0-9]|graphql|rpc|ac)\//i.test(parsedUrl.pathname) ||
                    parsedUrl.pathname === '/ac/' ||
                    parsedUrl.pathname.startsWith('/ac') ||
                    parsedUrl.pathname.endsWith('.json') ||
                    (req.headers['content-type']||'').includes('application/json') ||
                    (req.headers['accept']||'').includes('application/json');

  const fwdHeaders = {
    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':          isApiCall
                         ? 'application/json, text/plain, */*'
                         : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control':   'no-cache',
    'Pragma':          'no-cache',
    'Origin':          parsedUrl.origin,
    'Referer':         parsedUrl.origin + '/',
  };

  if (!isApiCall) {
    fwdHeaders['Upgrade-Insecure-Requests'] = '1';
    fwdHeaders['Sec-Fetch-Dest'] = 'document';
    fwdHeaders['Sec-Fetch-Mode'] = 'navigate';
    fwdHeaders['Sec-Fetch-Site'] = 'none';
  } else {
    fwdHeaders['Sec-Fetch-Dest'] = 'empty';
    fwdHeaders['Sec-Fetch-Mode'] = 'cors';
    fwdHeaders['Sec-Fetch-Site'] = 'same-origin';
    // Pass through YouTube/Google API headers
    [
      'content-type',
      'x-youtube-client-name','x-youtube-client-version',
      'x-goog-visitor-id','x-goog-authuser',
      'authorization','x-origin','x-goog-request-params',
    ].forEach(h => {
      const v = req.headers[h];
      if (v) fwdHeaders[h.replace(/-./g, m => m[1].toUpperCase())] = v;
    });
  }
  if (bodyContentType && !fwdHeaders['Content-Type'] && !fwdHeaders['content-type']) {
    fwdHeaders['Content-Type'] = bodyContentType;
  }
  if (req.headers['cookie']) fwdHeaders['Cookie'] = req.headers['cookie'];

  const ac    = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20_000);

  try {
    const upstream = await fetch(targetUrl, {
      method:   ['POST','PUT','PATCH','DELETE'].includes(method) ? method : 'GET',
      headers:  fwdHeaders,
      body:     body || undefined,
      redirect: 'follow',
      signal:   ac.signal,
    });
    clearTimeout(timer);

    for (const [k,v] of upstream.headers) {
      const kl = k.toLowerCase();
      if (STRIP_HEADERS.has(kl)) continue;
      if (kl === 'set-cookie') { res.setHeader('Set-Cookie', v); continue; }
      if (['etag','last-modified','cache-control','expires'].includes(kl)) res.setHeader(k, v);
    }
    applyCorsHeaders(res);

    const serverCT    = upstream.headers.get('content-type') || '';
    const enc         = upstream.headers.get('content-encoding') || '';
    const effectiveCT = guessTypeFromUrl(targetUrl, serverCT);

    // ── HTML ────────────────────────────────────────────────────────────────
    if (effectiveCT.includes('text/html')) {
      const raw  = Buffer.from(await upstream.arrayBuffer());
      let html   = (await decompress(raw, enc)).toString('utf8');
      const base = targetUrl;

      for (const [tag, attr] of [
        ['img','src'],['script','src'],['link','href'],
        ['video','src'],['audio','src'],['source','src'],
        ['input','src'],['iframe','src'],['track','src'],
        ['embed','src'],['object','data'],['video','poster'],
        ['img','data-src'],['img','data-lazy-src'],['img','data-original'],
        ['div','data-bg'],['section','data-bg'],['body','background'],
      ]) html = rewriteAttr(html, tag, attr, base, reqOrigin);

      html = rewriteSrcset(html, base, reqOrigin);

      // Forms
      html = html.replace(/(<form(?:\s[^>]*)?)\saction=([\"'])([^\"']+)\2/gi, (_m, pre, q, url) => {
        const p = proxyUrl(url, base, reqOrigin); return p ? `${pre} action=${q}${p}${q}` : _m;
      });
      // Inline styles
      html = html.replace(/(\sstyle=)([\"'])([^\"']*)\2/gi, (_m, pre, q, s) =>
        `${pre}${q}${rewriteCssUrls(s, base, reqOrigin)}${q}`
      );
      // <style> blocks
      html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
        (_m, open, css, close) => open + rewriteCssUrls(css, base, reqOrigin) + close
      );
      // Remove security headers from meta tags
      html = html
        .replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*\/?>/gi, '')
        .replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*\/?>/gi, '')
        .replace(/<meta[^>]*name=["']referrer["'][^>]*\/?>/gi, '');

      const rwScript   = buildRewriterScript(targetUrl, reqOrigin);
      const hasBase    = /<base\s[^>]*href/i.test(html);
      const baseTag    = hasBase ? '' : `<base href="${targetUrl}">`;
      const warnBanner = isPartialSupport(parsedUrl.hostname) ? buildWarningBanner(parsedUrl.hostname) : '';

      if (/<head[^>]*>/i.test(html)) {
        // Rewriter MUST be first thing in <head> — before any site scripts
        html = html.replace(/(<head[^>]*>)/i, `$1${baseTag}${rwScript}`);
        if (warnBanner) {
          if (/<\/body>/i.test(html)) html = html.replace(/<\/body>/i, warnBanner + '</body>');
          else html += warnBanner;
        }
      } else {
        html = baseTag + rwScript + html + warnBanner;
      }

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(upstream.status).send(html);
    }

    // ── CSS ───────────────────────────────────────────────────────────────────
    if (effectiveCT.includes('text/css')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const css = rewriteCssUrls((await decompress(raw, enc)).toString('utf8'), targetUrl, reqOrigin);
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
      return res.status(upstream.status).send(css);
    }

    // ── JavaScript ────────────────────────────────────────────────────────────
    if (effectiveCT.includes('javascript') || effectiveCT.includes('ecmascript')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const js  = (await decompress(raw, enc)).toString('utf8');
      // JavaScript is passed through as-is.
      // Client-side patchProto handles location.href assignments at runtime.
      res.setHeader('Content-Type', effectiveCT.includes(';') ? effectiveCT : effectiveCT + '; charset=utf-8');
      return res.status(upstream.status).send(js);
    }

    // ── JSON ─────────────────────────────────────────────────────────────────
    if (effectiveCT.includes('json')) {
      const raw = Buffer.from(await upstream.arrayBuffer());
      const txt = (await decompress(raw, enc)).toString('utf8');
      res.setHeader('Content-Type', serverCT || 'application/json');
      return res.status(upstream.status).send(txt);
    }

    // ── Binary pass-through ────────────────────────────────────────────────────
    res.setHeader('Content-Type', serverCT || 'application/octet-stream');
    return res.status(upstream.status).send(Buffer.from(await upstream.arrayBuffer()));

  } catch(err) {
    clearTimeout(timer);
    const timeout = err.name === 'AbortError';
    return res.status(timeout ? 504 : 502).send(errorPage(
      timeout ? 'Target server did not respond within 20 seconds.' : err.message,
      targetUrl, timeout ? 504 : 502
    ));
  }
};
