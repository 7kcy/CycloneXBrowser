export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { url } = req.query;
  if (!url) return res.status(400).send('Missing url param');

  let targetUrl;
  try {
    targetUrl = decodeURIComponent(url);
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;
    new URL(targetUrl); // validate
  } catch (e) {
    return res.status(400).send('Invalid URL');
  }

  try {
    const upstream = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'no-cache',
      },
      redirect: 'follow',
    });

    const contentType = upstream.headers.get('content-type') || 'text/html';

    // Strip framing-blocking headers, set permissive ones
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Frame-Options', 'ALLOWALL');
    res.setHeader('Content-Security-Policy', '');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Remove these headers from upstream by not forwarding them
    // Rewrite HTML to fix relative links
    if (contentType.includes('text/html')) {
      let html = await upstream.text();
      const base = new URL(targetUrl);
      const origin = base.origin;
      const baseHref = targetUrl;

      // Inject base tag and proxy rewriter script at the top of <head>
      const injected = `<base href="${baseHref}">
<script>
(function(){
  var PROXY = '/api/proxy?url=';
  var ORIGIN = '${origin}';
  var TARGET = '${targetUrl}';

  function proxyHref(href) {
    if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('data:') || href.startsWith('mailto:')) return href;
    try {
      var abs = new URL(href, TARGET).href;
      return PROXY + encodeURIComponent(abs);
    } catch(e) { return href; }
  }

  // Rewrite all links & forms on click/submit so navigation stays proxied
  document.addEventListener('click', function(e) {
    var a = e.target.closest('a');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
    try {
      var abs = new URL(href, TARGET).href;
      e.preventDefault();
      // Post message to parent (CycloneX) to navigate
      window.parent.postMessage({ type: 'cx-navigate', url: abs }, '*');
    } catch(e2) {}
  }, true);
})();
<\/script>`;

      // Insert after <head> or at start
      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/(<head[^>]*>)/i, '$1' + injected);
      } else {
        html = injected + html;
      }

      res.status(upstream.status).send(html);
    } else {
      // For non-HTML (images, CSS, JS etc.) stream through directly
      const buf = await upstream.arrayBuffer();
      res.status(upstream.status).send(Buffer.from(buf));
    }
  } catch (err) {
    res.status(502).send(`Proxy error: ${err.message}`);
  }
}
