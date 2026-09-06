/* SewaAstra Customer — 01-security-shims.js */
/* सबसे पहले चलने वाला code — SWXSS/SWID shim वग़ैरह.
   इसे किसी और script से पहले ही रहना चाहिए: यह innerHTML
   जैसे setters को लपेटता है, इसलिए देर से चला तो बेकार. */

/* ═══ inline ब्लॉक 1/1 ═══ */
/* ═══════════════════════════════════════════════════════════════
   SWXSS — आख़िरी सुरक्षा-जाल (v3)
   ---------------------------------------------------------------
   सोच: app में 300 जगह innerHTML है. हर एक पर सही escape लगाना और
        आगे भी लगा रहना — यह भरोसे की बात है, गारंटी की नहीं.
        एक जगह छूटी तो वही stored XSS बन जाती है.

        इसलिए escape को *आख़िरी दरवाज़े* पर रखा गया है: innerHTML का
        setter खुद. कोई भी रास्ता — पुराना कोड, नया कोड, भूली हुई जगह —
        सब यहीं से गुज़रते हैं.

   ⚠️ यह escape-at-source की जगह नहीं लेता. यह उसके नीचे का जाल है.
      दोनों साथ चाहिए.

   क्या हटाता है:
     • <script> <iframe> <object> <embed> <base> <link> <meta> <form>
       <svg> <math>  — इन apps के किसी template में ये आते ही नहीं,
       इसलिए हटाने से कुछ नहीं टूटता (जाँचा गया).
     • href/src/action में javascript: vbscript: data:text/html
     • on… attribute तभी हटते हैं जब उनमें साफ़ हमला दिखे
       (apps inline onclick पर टिके हैं — अंधाधुंध हटाना app तोड़ देता)
   ═══════════════════════════════════════════════════════════════ */
(function (global) {
  'use strict';
  if (global.SWXSS) return;

  // इन apps में ये tag कभी legitimately नहीं बनते
  var BAD = 'script|iframe|object|embed|base|link|meta|form|svg|math|frame|frameset|applet|template';

  var RE_PAIR = new RegExp('<\\s*(' + BAD + ')\\b[\\s\\S]*?<\\s*\\/\\s*\\1\\s*>', 'gi');
  var RE_ONE  = new RegExp('<\\s*\\/?\\s*(' + BAD + ')\\b[^>]*>', 'gi');

  // href/src/action में खतरनाक scheme.  data:image और data:video चलने दो.
  var RE_URL = /(\b(?:href|src|action|formaction|data|poster|xlink:href)\s*=\s*)(["']?)\s*(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|data\s*:\s*text\s*\/\s*html)\s*:?[^"'>\s]*/gi;

  // ── on… handler ──
  // ये apps 434 inline onclick पर टिकी हैं, इसलिए सबको हटाना app तोड़ देगा.
  // इसलिए दो परतें: (क) सिर्फ़ वही handler नाम चलेंगे जो apps सच में
  // इस्तेमाल करते हैं — onmouseover/onanimationstart/ontoggle जैसे
  // दर्जनों bypass रास्ते यहीं बंद. (ख) बचे हुए handler में जाना-पहचाना
  // payload दिखा तो वो भी हटेगा.
  var OK_ON = { onclick:1, onchange:1, oninput:1, onkeydown:1, onkeyup:1,
                onerror:1, onload:1, onsubmit:1, onblur:1, onfocus:1 };

  var RE_ON  = /(\s)(on\w+)(\s*=\s*)(["'])((?:(?!\4)[\s\S])*?)\4/gi;
  var RE_ON2 = /(\s)(on\w+)(\s*=\s*)([^\s"'>]+)/gi;      // बिना quote वाला

  // handler के अंदर ये कभी legitimately नहीं आते
  var RE_PAYLOAD = new RegExp([
    '<', 'javascript\\s*:', 'vbscript\\s*:', '&#', '\\\\x3c', '\\\\u003c',
    // function जैसे — पीछे ( या [ या . चाहिए
    '\\b(?:alert|prompt|confirm|eval|atob|btoa|unescape|decodeURI|fetch|import|Function|' +
      'setTimeout|setInterval|XMLHttpRequest|WebSocket|EventSource|Worker|open|write|' +
      'createElement|appendChild|insertAdjacent|setAttribute)\\s*[\\(\\[]',
    // ये नाम अकेले ही ख़तरा — कुछ पीछे लगने की ज़रूरत नहीं
    '\\b(?:document\\s*\\.\\s*cookie|localStorage|sessionStorage|indexedDB|' +
      'navigator\\s*\\.\\s*sendBeacon|location\\s*\\.\\s*(?:href|replace|assign)|' +
      'innerHTML|outerHTML|srcdoc|globalThis|constructor)\\b',
    // bracket से property निकालना — obfuscation का पसंदीदा रास्ता
    '\\b(?:window|self|top|parent|frames|document|this)\\s*\\['
  ].join('|'), 'i');

  var blocked = 0;

  function keepHandler(name, val) {
    if (!OK_ON[String(name).toLowerCase()]) { blocked++; return false; }
    if (RE_PAYLOAD.test(val)) { blocked++; return false; }
    return true;
  }

  function clean(html) {
    var s = String(html == null ? '' : html);
    if (s.indexOf('<') < 0 && s.indexOf('&') < 0) return s;   // सादा text — छोड़ो

    var before = s;
    s = s.replace(RE_PAIR, '').replace(RE_ONE, '');
    s = s.replace(RE_URL, function (m, p1, q) { blocked++; return p1 + q + '#blocked'; });
    s = s.replace(RE_ON, function (m, sp, name, eq, q, val) {
      return keepHandler(name, val) ? m : sp;
    });
    s = s.replace(RE_ON2, function (m, sp, name, eq, val) {
      return keepHandler(name, val) ? m : sp;
    });
    if (s !== before) blocked++;
    return s;
  }

  function wrapProp(proto, prop) {
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set || d.__swxss) return;
    var orig = d.set;
    Object.defineProperty(proto, prop, {
      configurable: true,
      enumerable: d.enumerable,
      get: d.get,
      set: function (v) { orig.call(this, clean(v)); }
    });
    Object.getOwnPropertyDescriptor(proto, prop).__swxss = 1;
  }

  try { wrapProp(Element.prototype, 'innerHTML'); } catch (e) {}
  try { wrapProp(Element.prototype, 'outerHTML'); } catch (e) {}

  try {
    var iah = Element.prototype.insertAdjacentHTML;
    if (iah && !iah.__swxss) {
      Element.prototype.insertAdjacentHTML = function (pos, html) {
        return iah.call(this, pos, clean(html));
      };
      Element.prototype.insertAdjacentHTML.__swxss = 1;
    }
  } catch (e) {}

  /** URL सुरक्षित है? src/href सीधे लगाने से पहले इससे गुज़ारें */
  function safeUrl(u) {
    var s = String(u == null ? '' : u).trim();
    if (!s) return '';
    if (/^(https?:|\/|\.\/|#|mailto:|tel:)/i.test(s)) return s;
    if (/^data:(image|video|audio)\//i.test(s)) return s;   // upload preview
    return '';                                              // बाकी सब बंद
  }

  /** HTML entity escape — escape-at-source के लिए */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"'`=\/]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
               "'": '&#39;', '`': '&#96;', '=': '&#61;', '/': '&#47;' }[c];
    });
  }

  global.SWXSS = {
    clean: clean,
    esc: esc,
    safeUrl: safeUrl,
    blocked: function () { return blocked; }
  };
  if (!global.swEsc) global.swEsc = esc;
})(window);
