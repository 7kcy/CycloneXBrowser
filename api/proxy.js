module.exports = async function handler(req, res) {
  // ── CORS ────────────────────────────────────────────────────────────────────
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Cookie');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // ── Parse & validate target URL ─────────────────────────────────────────────
  const { url, _cx_origin } = req.query;
  if (!url) return res.status(400).send('Missing url param');

  let targetUrl;
  try {
    targetUrl = decodeURIComponent(url);
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;
    new URL(targetUrl);
  } catch {
    return res.status(400).send('Invalid URL');
  }

  const parsedTarget = new URL(targetUrl);
  const proxyBase = req.headers['x-forwarded-proto']
    ? `${req.headers['x-forwarded-proto']}://${req.headers['x-forwarded-host'] || req.headers.host}`
    : `http://${req.headers.host}`;

  function reProxyUrl(href, base) {
    if (!href) return href;
    const trimmed = href.trim();
    if (trimmed.startsWith('data:') || trimmed.startsWith('blob:') ||
        trimmed.startsWith('javascript:') || trimmed.startsWith('#') ||
        trimmed.startsWith('mailto:') || trimmed.startsWith('tel:')) return trimmed;
    if (trimmed.startsWith('/api/proxy?url=')) return trimmed; // already proxied
    try {
      let abs = trimmed;
      if (trimmed.startsWith('//')) abs = 'https:' + trimmed;
      else abs = new URL(trimmed, base).href;
      return `${proxyBase}/api/proxy?url=${encodeURIComponent(abs)}`;
    } catch {
      return href;
    }
  }

  function rewriteCssUrls(css, base) {
    return css.replace(/url\(\s*(['"]?)([^)'"\n]+)\1\s*\)/gi, (_, q, u) => {
      return `url(${q}${reProxyUrl(u, base)}${q})`;
    });
  }

  function rewriteCssImports(css, base) {
    return css
      .replace(/@import\s+url\(\s*(['"]?)([^)'"\n]+)\1\s*\)/gi, (_, q, u) => `@import url(${q}${reProxyUrl(u, base)}${q})`)
      .replace(/@import\s+(['"])([^'"]+)\1/gi, (_, q, u) => `@import ${q}${reProxyUrl(u, base)}${q}`);
  }

  // ── Fetch upstream ─────────────────────────────────────────────────────────
  const forwardHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'identity',
    'Cache-Control': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Upgrade-Insecure-Requests': '1',
  };
  if (req.headers.cookie) forwardHeaders['Cookie'] = req.headers.cookie;
  if (_cx_origin) forwardHeaders['Referer'] = _cx_origin;

  let upstream;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method === 'POST' ? 'POST' : 'GET',
      headers: forwardHeaders,
      redirect: 'follow',
      body: req.method === 'POST' ? req.body : undefined,
    });
  } catch (err) {
    return res.status(502).send(`<html><body style="font-family:monospace;padding:40px;background:#0a0a0a;color:#f00"><h2>Proxy Error</h2><p>${err.message}</p></body></html>`);
  }

  // Forward cleaned Set-Cookie
  const rawHeaders = upstream.headers.raw ? upstream.headers.raw() : {};
  if (rawHeaders['set-cookie']) {
    const cleaned = rawHeaders['set-cookie'].map(c =>
      c.replace(/;\s*Domain=[^;]+/gi, '').replace(/;\s*Secure/gi, '').replace(/;\s*SameSite=[^;]+/gi, '')
    );
    res.setHeader('Set-Cookie', cleaned);
  }

  const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
  const isHtml = contentType.includes('text/html');
  const isCss  = contentType.includes('text/css');
  const isText = isHtml || isCss || contentType.includes('javascript') || contentType.includes('svg') || contentType.includes('text/');

  const STRIP = new Set([
    'x-frame-options','content-security-policy','content-security-policy-report-only',
    'cross-origin-embedder-policy','cross-origin-opener-policy','cross-origin-resource-policy',
    'permissions-policy','strict-transport-security','set-cookie','content-encoding',
    'content-length','transfer-encoding',
  ]);
  for (const [k, v] of upstream.headers.entries()) {
    if (!STRIP.has(k.toLowerCase())) res.setHeader(k, v);
  }
  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Proxy-By', 'CycloneX-v5');

  // Binary passthrough
  if (!isText) {
    const buf = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(buf));
  }

  // Decode text with correct charset
  const rawBuf = await upstream.arrayBuffer();
  const charsetMatch = contentType.match(/charset=([^\s;]+)/i);
  let body;
  try {
    body = new TextDecoder(charsetMatch ? charsetMatch[1] : 'utf-8', { fatal: false }).decode(rawBuf);
  } catch {
    body = new TextDecoder('utf-8', { fatal: false }).decode(rawBuf);
  }

  if (isCss) {
    body = rewriteCssUrls(rewriteCssImports(body, targetUrl), targetUrl);
    return res.status(upstream.status).send(body);
  }

  if (isHtml) {
    const origin = parsedTarget.origin;

    // Rewrite src/href/action/srcset attributes
    body = body
      .replace(/((?:src|href|action|data-src|data-href)\s*=\s*)(['"])(.*?)\2/gi, (_, attr, q, val) => {
        const v = val.trim();
        if (v.startsWith('//')) return `${attr}${q}${reProxyUrl('https:' + v, targetUrl)}${q}`;
        return `${attr}${q}${reProxyUrl(val, targetUrl)}${q}`;
      })
      .replace(/(srcset\s*=\s*)(['"])(.*?)\2/gi, (_, attr, q, val) => {
        const rw = val.replace(/([^\s,]+)(\s+[\w.]+)?/g, (m, u, d) => reProxyUrl(u.trim(), targetUrl) + (d || ''));
        return `${attr}${q}${rw}${q}`;
      })
      .replace(/(style\s*=\s*)(['"])(.*?)\2/gi, (_, attr, q, val) => `${attr}${q}${rewriteCssUrls(val, targetUrl)}${q}`);

    // Rewrite <style> blocks
    body = body.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
      (_, open, css, close) => open + rewriteCssUrls(rewriteCssImports(css, targetUrl), targetUrl) + close);

    // Block meta refresh
    body = body.replace(/<meta\s+http-equiv\s*=\s*['"]refresh['"]/gi, '<meta data-cx-blocked-refresh');

    const script = `
<base href="${targetUrl}">
<script>
(function(){
  var PROXY='/api/proxy?url=';
  var PAGE='${targetUrl.replace(/'/g,"\\'")}';
  var ORIGIN='${origin.replace(/'/g,"\\'")}';
  function proxied(href,ctx){
    if(!href)return href;
    var h=href.trim();
    if(/^(javascript:|#|data:|blob:|mailto:|tel:)/.test(h))return href;
    if(h.startsWith('/api/proxy?url='))return h;
    try{var a=new URL(h.startsWith('//')?'https:'+h:h,ctx||PAGE).href;return PROXY+encodeURIComponent(a);}catch(e){return href;}
  }
  // Clicks
  document.addEventListener('click',function(e){
    var a=e.target.closest('a[href]');
    if(!a)return;
    var href=a.getAttribute('href');
    if(!href||/^(#|javascript:)/.test(href.trim()))return;
    e.preventDefault();e.stopPropagation();
    try{window.parent.postMessage({type:'cx-navigate',url:new URL(href,PAGE).href},'*');}catch(ex){}
  },true);
  // Forms
  document.addEventListener('submit',function(e){
    var f=e.target;if(!f)return;
    e.preventDefault();
    var action=new URL(f.getAttribute('action')||PAGE,PAGE).href;
    var method=(f.getAttribute('method')||'GET').toUpperCase();
    var params=new URLSearchParams(new FormData(f)).toString();
    var dest=method==='GET'?(action+(params?'?'+params:'')):(action);
    window.parent.postMessage({type:'cx-navigate',url:dest},'*');
  },true);
  // SPA history
  ['pushState','replaceState'].forEach(function(fn){
    var orig=history[fn].bind(history);
    history[fn]=function(s,t,u){
      if(u)try{window.parent.postMessage({type:'cx-url-update',url:new URL(String(u),PAGE).href},'*');}catch(e){}
      return orig(s,t,u);
    };
  });
  // XHR proxy
  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    try{var a=new URL(u,PAGE).href;if(a.startsWith(ORIGIN))arguments[1]=PROXY+encodeURIComponent(a);}catch(e){}
    return _open.apply(this,arguments);
  };
  // fetch proxy
  var _fetch=window.fetch;
  window.fetch=function(input,init){
    try{
      var u=typeof input==='string'?input:(input&&input.url)||input;
      var a=new URL(u,PAGE).href;
      if(a.startsWith(ORIGIN)){
        var p=PROXY+encodeURIComponent(a);
        input=typeof input==='string'?p:new Request(p,input);
      }
    }catch(e){}
    return _fetch(input,init);
  };
})();
<\/script>`;

    const insertAfter = /<head[^>]*>/i.test(body) ? /(<head[^>]*>)/i
                       : /<html[^>]*>/i.test(body) ? /(<html[^>]*>)/i
                       : null;
    body = insertAfter ? body.replace(insertAfter, '$1' + script) : script + body;
    return res.status(upstream.status).send(body);
  }

  return res.status(upstream.status).send(body);
};
