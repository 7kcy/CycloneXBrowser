module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('Missing url param');

  try {
    targetUrl = decodeURIComponent(targetUrl);
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;
    new URL(targetUrl);
  } catch (e) {
    return res.status(400).send('Invalid URL');
  }

  // Forward body for POST (form submits)
  let body = undefined;
  let bodyContentType = undefined;
  if (req.method === 'POST') {
    const ct = req.headers['content-type'] || '';
    if (typeof req.body === 'object' && req.body !== null) {
      if (ct.includes('application/x-www-form-urlencoded')) {
        body = new URLSearchParams(req.body).toString();
        bodyContentType = 'application/x-www-form-urlencoded';
      } else {
        body = JSON.stringify(req.body);
        bodyContentType = 'application/json';
      }
    } else if (typeof req.body === 'string') {
      body = req.body;
      bodyContentType = ct;
    }
  }

  const base = new URL(targetUrl);
  const forwardHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'identity',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Referer': base.origin + '/',
  };
  if (bodyContentType) forwardHeaders['Content-Type'] = bodyContentType;
  if (req.headers['cookie']) forwardHeaders['Cookie'] = req.headers['cookie'];

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method === 'POST' ? 'POST' : 'GET',
      headers: forwardHeaders,
      body: body,
      redirect: 'follow',
    });

    const setCookie = upstream.headers.get('set-cookie');
    if (setCookie) res.setHeader('Set-Cookie', setCookie);

    const contentType = upstream.headers.get('content-type') || '';

    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Content-Security-Policy', '');
    res.setHeader('Access-Control-Allow-Origin', '*');

    // ── HTML: full rewrite ──────────────────────────────────────────────────
    if (contentType.includes('text/html')) {
      let html = await upstream.text();
      const origin = base.origin;

      const rewriterScript = `<script>
(function(){
  var PROXY = '/api/proxy?url=';
  var PAGE_URL = '${targetUrl.replace(/'/g, "\\'")}';
  var PAGE_ORIGIN = '${origin.replace(/'/g, "\\'")}';

  function toAbs(href) {
    if (!href) return null;
    if (/^(javascript:|#|data:|mailto:|tel:)/i.test(href)) return null;
    try { return new URL(href, PAGE_URL).href; } catch(e) { return null; }
  }

  // Intercept <a> clicks — navigate via parent
  document.addEventListener('click', function(e) {
    var el = e.target.closest('a[href]');
    if (!el) return;
    var href = el.getAttribute('href');
    if (!href || /^(javascript:|#|mailto:|tel:)/i.test(href)) return;
    var a = toAbs(href);
    if (!a) return;
    e.preventDefault();
    e.stopPropagation();
    window.parent.postMessage({ type: 'cx-navigate', url: a }, '*');
  }, true);

  // Intercept <form> submits
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM') return;
    e.preventDefault();
    e.stopPropagation();
    var action = form.getAttribute('action') || PAGE_URL;
    var method = (form.getAttribute('method') || 'GET').toUpperCase();
    var a = toAbs(action) || PAGE_URL;
    var data = new FormData(form);
    if (method === 'GET') {
      var params = new URLSearchParams();
      data.forEach(function(v,k){ params.append(k,v); });
      window.parent.postMessage({ type: 'cx-navigate', url: a.split('?')[0] + '?' + params.toString() }, '*');
    } else {
      var params2 = new URLSearchParams();
      data.forEach(function(v,k){ params2.append(k,v); });
      window.parent.postMessage({ type: 'cx-navigate', url: a, method: 'POST', body: params2.toString() }, '*');
    }
  }, true);

  // Intercept history.pushState / replaceState
  ['pushState','replaceState'].forEach(function(fn) {
    var orig = history[fn].bind(history);
    history[fn] = function(state, title, url) {
      if (!url) { try { orig(state, title, url); } catch(e) {} return; }
      var a = toAbs(String(url));
      if (a) {
        // Try rewriting the URL to stay within the proxy origin
        try { orig(state, title, PROXY + encodeURIComponent(a)); }
        catch(e) { window.parent.postMessage({ type: 'cx-navigate', url: a }, '*'); }
      } else {
        try { orig(state, title, url); } catch(e) {}
      }
    };
  });

  // Proxy fetch()
  var _fetch = window.fetch;
  window.fetch = function(input, init) {
    var url = typeof input === 'string' ? input
            : (input instanceof Request) ? input.url
            : (input && input.url) || '';
    var a = toAbs(url);
    if (a && !a.startsWith(location.origin)) {
      // Rewrite to proxy; if input was a Request object, rebuild as string
      input = PROXY + encodeURIComponent(a);
      // Strip credentials mode that would cause CORS preflight failures
      init = Object.assign({}, init || {}, { credentials: 'omit', mode: 'cors' });
    }
    return _fetch(input, init);
  };

  // Proxy XMLHttpRequest
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    var a = toAbs(url);
    if (a && !a.startsWith(location.origin)) url = PROXY + encodeURIComponent(a);
    return _open.call(this, method, url, async !== false, user, pass);
  };
})();
<\/script>`;

      // Rewrite src/href attributes for sub-resources
      function rewriteAttr(h, tag, attr) {
        return h.replace(new RegExp('(<' + tag + '[^>]*\\s' + attr + '=["\'])([^"\']+)(["\'])', 'gi'), function(m, pre, url, post) {
          if (!url || /^(data:|javascript:|#|about:|blob:)/i.test(url)) return m;
          try { return pre + '/api/proxy?url=' + encodeURIComponent(new URL(url, targetUrl).href) + post; }
          catch(e) { return m; }
        });
      }

      html = rewriteAttr(html, 'img',    'src');
      html = rewriteAttr(html, 'script', 'src');
      html = rewriteAttr(html, 'link',   'href');
      html = rewriteAttr(html, 'video',  'src');
      html = rewriteAttr(html, 'audio',  'src');
      html = rewriteAttr(html, 'source', 'src');
      html = rewriteAttr(html, 'input',  'src');

      // Rewrite <form action>
      html = html.replace(/(<form[^>]*\saction=["'])([^"']+)(["'])/gi, function(m, pre, url, post) {
        try { return pre + '/api/proxy?url=' + encodeURIComponent(new URL(url, targetUrl).href) + post; }
        catch(e) { return m; }
      });

      // Rewrite inline url() in style attributes & <style> blocks
      html = html.replace(/url\(["']?([^)"'\s]+)["']?\)/g, function(m, url) {
        if (!url || /^(data:|#|blob:)/i.test(url)) return m;
        try { return "url('/api/proxy?url=" + encodeURIComponent(new URL(url, targetUrl).href) + "')"; }
        catch(e) { return m; }
      });

      // Remove CSP / frame-options meta tags
      html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*\/?>/gi, '');
      html = html.replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*\/?>/gi, '');

      // Inject base tag + rewriter script.
      // The rewriter MUST run before any page scripts (including async/defer)
      // so interceptors are in place before Google's JS fires XHR/fetch calls.
      const baseTag = '<base href="' + targetUrl + '">';
      if (/<head[^>]*>/i.test(html)) {
        // 1. Insert <base> right after <head>
        html = html.replace(/(<head[^>]*>)/i, '$1' + baseTag);
        // 2. Insert rewriter immediately before the first <script so it runs first
        if (/<script/i.test(html)) {
          html = html.replace(/(<script)/i, rewriterScript + '$1');
        } else {
          html = html.replace(/(<\/head>)/i, rewriterScript + '$1');
        }
      } else {
        html = baseTag + rewriterScript + html;
      }

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(upstream.status).send(html);
    }

    // ── CSS: rewrite url() and @import ─────────────────────────────────────
    if (contentType.includes('text/css')) {
      let css = await upstream.text();
      css = css.replace(/url\(["']?([^)"'\s]+)["']?\)/g, function(m, url) {
        if (!url || /^(data:|#|blob:)/i.test(url)) return m;
        try { return "url('/api/proxy?url=" + encodeURIComponent(new URL(url, targetUrl).href) + "')"; }
        catch(e) { return m; }
      });
      css = css.replace(/@import\s+["']([^"']+)["']/g, function(m, url) {
        try { return "@import '/api/proxy?url=" + encodeURIComponent(new URL(url, targetUrl).href) + "'"; }
        catch(e) { return m; }
      });
      res.setHeader('Content-Type', contentType);
      return res.status(upstream.status).send(css);
    }

    // ── Everything else: pass through ──────────────────────────────────────
    res.setHeader('Content-Type', contentType);
    const buf = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(buf));

  } catch (err) {
    return res.status(502).send(
      '<html><body style="font-family:monospace;padding:40px;background:#0a0a0a;color:#ff6060">' +
      '<h2>Proxy Error</h2><p>' + err.message + '</p>' +
      '<p style="color:#666">Target: ' + targetUrl + '</p>' +
      '</body></html>'
    );
  }
};
