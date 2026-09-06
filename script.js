/* SewaAstra Customer — सारा JavaScript, मूल क्रम में (50 ब्लॉक)

   ⚠️ क्रम मत बदलिए. सबसे ऊपर security shims (SWXSS/SWID) हैं — वे
   ⚠️ क्रम मत बदलिए. सबसे ऊपर security shims (SWXSS/SWID) हैं — वे
   ⚠️ क्रम मत बदलिए. सबसे ऊपर security shims (SWXSS/SWID) हैं — वे
      innerHTML जैसे setters को लपेटकर XSS रोकते हैं. अगर उन्हें नीचे
      खिसकाया या हटाया, तो नीचे का सारा code बिना पहरे के चलेगा.

   हर ब्लॉक अपने try/catch में है ताकि एक जगह की गड़बड़ बाक़ी ऐप को न ले डूबे.
   कोई ब्लॉक गिरे तो console में साफ़ लिखा आएगा, और window.__SW_ERRORS में
   उसकी गिनती मिल जाएगी.

   (48/50 ब्लॉक लपेटे गए; 2 जान-बूझकर छोड़े गए — कारण वहीं लिखा है.
    जाँच: acorn)
*/

/* ═══ ब्लॉक 0 ═══ */
try {
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
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 0 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([0, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 1 ═══ */
try {
window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-52QKXTC1J4');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 1 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([1, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 2 ═══ */
try {
window.__SWID_ROLE = 'customer';
/* ═══════════════════════════════════════════════════════════════
   SWID — पहचान की एक ही जगह (v3)
   ---------------------------------------------------------------
   समस्या: पूरे app में doc ID के तौर पर फोन नंबर इस्तेमाल हुआ है
           (partners/9111111111). फोन नंबर बदला जा सकता है, अंदाज़ा
           लगाया जा सकता है, और recycle होता है — इसलिए वो पहचान
           का आधार नहीं हो सकता. सही आधार Firebase Auth का uid है.

   हल:    65+ जगह हाथ से बदलने के बजाय Firestore की doc() call को
          एक बार लपेट देते हैं. सिर्फ *अपना* फोन नंबर चुपचाप अपने
          uid पर मुड़ता है — किसी और का ID कभी नहीं छुआ जाता.

   खुद ठीक होने वाला: boot पर देखता है कि uid-वाला doc बना है या
          नहीं. migration के हर चरण में सही जगह पर जाता है, चाहे
          phase1 चल रहा हो या phase3 हो चुका हो.
   ═══════════════════════════════════════════════════════════════ */
(function (global) {
  'use strict';
  if (global.SWID) return;

  var KEYED = { partners: 1, users: 1 };   // सिर्फ ये दो collections
  var _uid = null;                          // Firebase Auth uid
  var _phone = '';                          // मेरा 10-अंकी नंबर
  var _docId = '';                          // असल में कौन-सा ID इस्तेमाल हो
  var _resolved = false;
  var _waiters = [];
  var LS = 'swid_docmode_v3';

  function digits10(s) {
    s = String(s == null ? '' : s).replace(/\D/g, '');
    return s.length >= 10 ? s.slice(-10) : '';
  }

  /** मेरा फोन — auth token सबसे भरोसेमंद, localStorage सिर्फ सहारा */
  function readPhone() {
    try {
      var u = global.firebase && firebase.auth().currentUser;
      if (u && u.phoneNumber) return digits10(u.phoneNumber);
    } catch (e) {}
    try {
      var a = localStorage.getItem('swp_phone') || localStorage.getItem('sw_user') || '';
      return digits10(a);
    } catch (e) {}
    return '';
  }

  /**
   * तय करो कि मेरा doc uid पर है या अभी भी फोन पर.
   * phase2 के बाद uid-doc मौजूद होगा → uid.
   * उससे पहले → फोन (कुछ नहीं टूटता).
   */
  function resolve(FS) {
    if (_resolved) return Promise.resolve(_docId);
    _uid = null;
    try { var u = firebase.auth().currentUser; if (u) _uid = u.uid; } catch (e) {}
    _phone = readPhone();

    // logged out — कोई redirect नहीं, पर waiters ज़रूर छोड़ो
    if (!_uid) { _docId = _phone; finish(); return Promise.resolve(_docId); }
    if (!_phone) { _docId = _uid; finish(); return Promise.resolve(_docId); }

    // पिछली बार का फ़ैसला याद है?
    try {
      var c = JSON.parse(localStorage.getItem(LS) || 'null');
      if (c && c.uid === _uid && c.mode === 'uid') {
        _docId = _uid; finish(); return Promise.resolve(_docId);
      }
    } catch (e) {}

    var coll = (global.__SWID_ROLE === 'customer') ? 'users' : 'partners';
    return rawDoc(FS, coll, _uid).get()
      .then(function (s) {
        _docId = s.exists ? _uid : _phone;
        if (s.exists) { try { localStorage.setItem(LS, JSON.stringify({ uid: _uid, mode: 'uid' })); } catch (e) {} }
        finish(); return _docId;
      })
      .catch(function () {
        // rules ने रोका या network — सुरक्षित रास्ता: पुराना ID
        _docId = _phone || _uid; finish(); return _docId;
      });
  }

  function finish() {
    _resolved = true;
    var w = _waiters; _waiters = [];
    w.forEach(function (fn) { try { fn(_docId); } catch (e) {} });
  }

  var _raw = null;   // लपेटने से पहले वाला असली collection()
  function rawDoc(FS, coll, id) {
    return (_raw ? _raw.call(FS, coll) : FS.collection(coll)).doc(id);
  }

  /**
   * ID अनुवाद — यही पूरे shim का दिल.
   * सिर्फ तब बदलता है जब ID *बिलकुल मेरा अपना फोन नंबर* हो.
   * किसी और का नंबर, कोई uid, कोई code — सब वैसे के वैसे.
   */
  function map(coll, id) {
    if (!KEYED[coll]) return id;
    if (id == null) return id;
    var s = String(id);
    if (!_uid || !_phone) return id;
    if (s === _phone && _docId === _uid) return _uid;
    return id;
  }

  global.SWID = {
    /** Firestore instance को लपेटो — app boot पर एक बार */
    install: function (FS) {
      if (!FS || FS.__swidWrapped) return FS;
      _raw = FS.collection;
      FS.collection = function (name) {
        var c = _raw.call(this, name);
        if (KEYED[name] && !c.__swidDoc) {
          var origDoc = c.doc.bind(c);
          c.doc = function (id) { return origDoc(map(name, id)); };
          c.__swidDoc = 1;
        }
        return c;
      };
      FS.__swidWrapped = 1;

      // auth बदले तो पहचान दोबारा तय करो
      try {
        firebase.auth().onAuthStateChanged(function () {
          _resolved = false; _docId = ''; resolve(FS);
        });
      } catch (e) {}
      resolve(FS);
      return FS;
    },


    /**
     * orders पर सही पहचान-field चुनो.
     * migration हो चुका (mine()==uid) → partnerUid / uid
     * उससे पहले                        → partnerPhone / mobile
     * लौटाता है [field, value] या null अगर पहचान ही नहीं.
     */
    orderKey: function (role) {
      var byUid = !!(_uid && _docId === _uid);
      if (role === 'partner') {
        if (byUid) return ['partnerUid', _uid];
        return _phone ? ['partnerPhone', _phone] : null;
      }
      if (byUid) return ['uid', _uid];
      return _phone ? ['mobile', _phone] : null;
    },

    /** सीधे query बना दो — null अगर पहचान नहीं */
    orderQuery: function (FS, role) {
      var k = this.orderKey(role);
      // 🔒 rules में orders.list पर capped(100) है — बिना .limit() के
      //    पूरी query reject हो जाती थी और अपने ही orders नहीं दिखते थे.
      return k ? FS.collection('orders').where(k[0], '==', k[1]).limit(100) : null;
    },

    uid: function () { return _uid || ''; },
    phone: function () { return _phone; },
    /** मेरा असली doc ID — uid (या migration से पहले फोन) */
    mine: function () { return _docId || _uid || _phone; },
    ready: function (cb) { _resolved ? cb(_docId) : _waiters.push(cb); },
    /** order पर मालिकाना — uid पहले, पुराने orders के लिए फोन */
    ownsOrder: function (o) {
      if (!o) return false;
      if (o.partnerUid) return o.partnerUid === _uid;
      if (o.uid) return o.uid === _uid;
      return !!(_phone && (o.partnerPhone === _phone || o.mobile === _phone));
    },
    /** नया order/doc लिखते वक़्त दोनों field भरो */
    stamp: function (obj) {
      obj = obj || {};
      if (_uid) obj.uid = _uid;
      if (_phone) obj.phone = _phone;
      return obj;
    },
    _map: map
  };
})(window);
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 2 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([2, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 3 ═══ */
try {
(function(){
  'use strict';
  var SW = window.SWSec = {};

  /* ── 1. HTML escaping — XSS की पहली दीवार ── */
  var MAP={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'};
  SW.esc = function(s){ return String(s==null?'':s).replace(/[&<>"'\/`=]/g, function(c){ return MAP[c]; }); };
  SW.escAttr = function(s){ return SW.esc(s).replace(/\s/g,'&#32;'); };
  /* URL sanitize — javascript: / data: वाले हमले रोके */
  SW.safeUrl = function(u){
    u = String(u||'').trim();
    if(/^(javascript|data|vbscript|file):/i.test(u.replace(/[\s\u0000-\u001f]/g,''))) return '#';
    return u;
  };

  /* ── 2. ROLE — सिर्फ Firebase ID token custom claim से. localStorage से कभी नहीं ── */
  var _claims = Object.create(null);
  var _ready  = false;
  var _waiters = [];

  SW.refreshClaims = function(force){
    return new Promise(function(res){
      try{
        var u = firebase.auth().currentUser;
        if(!u){ _claims = Object.create(null); _ready = true; return res(_claims); }
        u.getIdTokenResult(!!force).then(function(t){
          _claims = Object.freeze({
            admin:   t.claims.admin   === true,
            partner: t.claims.partner === true,
            phone:   String(t.claims.phone || '')
          });
          _ready = true;
          _waiters.splice(0).forEach(function(f){ try{f(_claims);}catch(e){} });
          res(_claims);
        }).catch(function(){ _claims=Object.create(null); _ready=true; res(_claims); });
      }catch(e){ _claims=Object.create(null); _ready=true; res(_claims); }
    });
  };

  /* 🔒 ये getters हैं — कोई इन्हें console से true नहीं कर सकता */
  Object.defineProperty(SW,'isAdmin',  {get:function(){ return _claims.admin===true; }, configurable:false});
  Object.defineProperty(SW,'isPartner',{get:function(){ return _claims.partner===true; }, configurable:false});
  Object.defineProperty(SW,'phone',    {get:function(){ return _claims.phone||''; }, configurable:false});
  Object.defineProperty(SW,'ready',    {get:function(){ return _ready; }, configurable:false});
  Object.freeze(SW.esc); Object.freeze(SW.safeUrl);

  SW.onReady = function(cb){ if(_ready) cb(_claims); else _waiters.push(cb); };

  /* ── 3. Server से claims sync (login के बाद) ── */
  SW.syncClaims = function(){
    try{
      if(!firebase.functions) return SW.refreshClaims(true);
      return firebase.app().functions('asia-south1')
        .httpsCallable('syncMyClaims')()
        .then(function(){ return SW.refreshClaims(true); })
        .catch(function(){ return SW.refreshClaims(true); });
    }catch(e){ return SW.refreshClaims(true); }
  };

  /* ── 4. Callable helper — सारे संवेदनशील काम server पर ── */
  SW.call = function(name, data){
    try{
      return firebase.app().functions('asia-south1').httpsCallable(name)(data||{})
        .then(function(r){ return r.data; });
    }catch(e){ return Promise.reject(e); }
  };

  /* ── 5. Auth state पर claims हमेशा ताज़ा रखो ── */
  function hook(){
    if(!window.firebase || !firebase.auth) return setTimeout(hook, 120);
    var _synced = false;
    firebase.auth().onAuthStateChanged(function(u){
      /* 🔑 claim server पर बनता है, login पर अपने आप नहीं आता.
         पहली बार user दिखते ही एक बार sync कराओ — वरना असली admin/partner
         भी बाहर ही खड़ा रह जाता है. (यह call पहले कहीं से होती ही नहीं थी.) */
      if (u && !_synced) {
        _synced = true;
        try { SW.syncClaims(); } catch (e) {}
      }
      if (!u) _synced = false;

      SW.refreshClaims(true).then(function(c){
        document.documentElement.setAttribute('data-role',
          c.admin ? 'admin' : (c.partner ? 'partner' : (u ? 'user' : 'guest')));
        /* admin-only UI सिर्फ असली admin को */
        try{
          document.querySelectorAll('[data-admin-only]').forEach(function(el){
            el.style.display = c.admin ? '' : 'none';
          });
        }catch(e){}
        try{ window.dispatchEvent(new CustomEvent('sw:claims', {detail:c})); }catch(e){}
      });
    });
    /* हर 30 मिनट token refresh — revoke तुरंत असर करे */
    setInterval(function(){ SW.refreshClaims(true); }, 30*60*1000);
  }
  hook();

  /* ── 6. localStorage के नकली admin flags हमेशा साफ़ ── */
  try{
    ['sw_is_admin','swp_is_admin','is_admin','admin'].forEach(function(k){
      try{ localStorage.removeItem(k); }catch(e){}
    });
    var _si = localStorage.setItem.bind(localStorage);
    localStorage.setItem = function(k,v){
      if(/^(sw_is_admin|swp_is_admin|is_admin|admin)$/i.test(String(k))){
        console.warn('[SWSec] blocked fake admin flag:', k);
        return;
      }
      return _si(k,v);
    };
  }catch(e){}

  /* ── 7. Clickjacking से बचाव ── */
  try{ if(window.top !== window.self) window.top.location = window.self.location; }catch(e){}

  console.log('%c🔒 SewaAstra Security Core active','background:#15a04a;color:#fff;padding:3px 8px;font-weight:bold;border-radius:4px');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 3 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([3, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 4 ═══ */
try {
/* ═══════════════════════════════════════════════════════════════════════
   🛡️ SWGuard — चुराए हुए session से बचाव (client हिस्सा)

   माँग थी "हर 10 सेकंड IP बदले." ब्राउज़र IP बदल नहीं सकता — वह ISP का
   होता है. और डेटा IP से चुराया भी नहीं जाता; चोरी तब होती है जब किसी के
   हाथ आपका session लग जाए. इसलिए यहाँ IP छिपाई नहीं, IP पर नज़र रखी जाती है.

   ── तीन परतें ──

   1. तुरंत logout (onSnapshot)
        security_sessions/{uid} को realtime सुनते हैं. server जैसे ही
        revoked:true लिखता है, logout *तुरंत* — एक सेकंड से भी कम.
        यह 10 सेकंड वाली जाँच से तेज़ है, इसलिए यही मुख्य परत है.

   2. हर 10 सेकंड स्थानीय जाँच
        निष्क्रियता का हिसाब, और listener ज़िंदा है या नहीं. कुछ भी
        गड़बड़ लगे तो तुरंत server से पूछ लेते हैं.

   3. हर 60 सेकंड server ping
        यहीं IP/device की असली जाँच होती है — server req.rawRequest से
        IP पढ़ता है, client से नहीं, इसलिए इसे झुठलाया नहीं जा सकता.

   ⚠️ ping 10 सेकंड पर क्यों नहीं?
      10 सेकंड = हर user रोज़ 8,640 call. 100 users पर महीने के ~2.6 करोड़
      invocation — Cloud Functions की मुफ़्त सीमा 20 लाख/महीना है. यानी
      बिल हज़ारों में चला जाता. 60 सेकंड पर वही सुरक्षा छठे ख़र्च में मिलती
      है, क्योंकि असली तेज़ी परत 1 से आती है, ping से नहीं.
      बदलना हो तो नीचे PING_MS बदल दीजिए.

   ⚠️ यह client code सुरक्षा *लागू* नहीं करता — सिर्फ़ पालन करता है.
      असली रोक Firestore rules और Cloud Function में है. कोई DevTools से
      SWGuard बंद कर दे तो भी server उसका session मार चुका होगा, और
      rules उसे कुछ पढ़ने-लिखने नहीं देंगे.
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  if (window.SWGuard) return;

  var TICK_MS  = 10 * 1000;        // स्थानीय जाँच — आपने यही माँगा था
  var PING_MS  = 60 * 1000;        // server से IP/device जाँच
  var IDLE_MS  = 10 * 60 * 1000;   // इतनी देर कुछ न किया तो logout
  var WARN_MS  = 60 * 1000;        // logout से कितनी देर पहले चेतावनी

  var sid = '', unsub = null, tick = null, lastPing = 0, lastAct = Date.now();
  var warned = false, dying = false, started = false;

  function newSid() {
    // crypto.randomUUID हर जगह नहीं है (पुराने Safari/WebView) — इसलिए fallback.
    try { if (crypto && crypto.randomUUID) return crypto.randomUUID(); } catch (e) {}
    try {
      var a = new Uint8Array(16); crypto.getRandomValues(a);
      return Array.prototype.map.call(a, function (b) {
        return ('0' + b.toString(16)).slice(-2);
      }).join('');
    } catch (e) {}
    return 'sid' + Date.now() + Math.random().toString(36).slice(2);
  }

  var REASONS = {
    'device-badla':          'आपका account किसी दूसरे device पर खुला मिला।',
    'do-jagah-se-chal-raha': 'आपका account एक ही समय पर दो जगह से चल रहा था।',
    'nishkriya':             'काफ़ी देर तक कोई गतिविधि नहीं हुई।',
    'revoked':               'सुरक्षा कारणों से session बंद कर दिया गया।'
  };

  function kill(reason) {
    if (dying) return;
    dying = true;
    stop();
    var msg = REASONS[reason] || REASONS.revoked;
    try {
      firebase.auth().signOut().catch(function () {});
    } catch (e) {}
    // सारा स्थानीय डेटा भी हटाओ — साझा कंप्यूटर पर यही बचा रह जाता है
    try { sessionStorage.clear(); } catch (e) {}
    try {
      Object.keys(localStorage).forEach(function (k) {
        if (/^(sw|firebase|cart|order)/i.test(k)) localStorage.removeItem(k);
      });
    } catch (e) {}
    showBox(msg);
  }

  function showBox(msg) {
    try {
      if (document.getElementById('swg-box')) return;
      var d = document.createElement('div');
      d.id = 'swg-box';
      d.setAttribute('style',
        'position:fixed;inset:0;z-index:2147483647;background:rgba(6,10,20,.94);' +
        'display:flex;align-items:center;justify-content:center;padding:22px;' +
        'font-family:system-ui,sans-serif;color:#e8eefc');
      var card = document.createElement('div');
      card.setAttribute('style',
        'max-width:400px;background:#101c33;border:1px solid #2a3f66;border-radius:16px;' +
        'padding:26px;text-align:center;line-height:1.7');
      var h = document.createElement('div');
      h.setAttribute('style', 'font-size:38px;margin-bottom:6px');
      h.textContent = '🔒';
      var t = document.createElement('div');
      t.setAttribute('style', 'font-size:19px;font-weight:700;margin-bottom:8px');
      t.textContent = 'Session बंद कर दिया गया';
      var p = document.createElement('div');
      p.setAttribute('style', 'font-size:14px;color:#b9c7e6;margin-bottom:20px');
      p.textContent = msg + ' सुरक्षा के लिए आपको बाहर कर दिया गया है। कृपया दोबारा login करें।';
      var b = document.createElement('button');
      b.setAttribute('style',
        'background:#2563eb;color:#fff;border:0;border-radius:10px;padding:11px 26px;' +
        'font-size:15px;font-weight:600;cursor:pointer');
      b.textContent = 'दोबारा login करें';
      b.onclick = function () { location.reload(); };
      // textContent इस्तेमाल किया, innerHTML नहीं — reason server से आता है
      // और उसे सीधे HTML में डालना XSS का रास्ता खोल देता.
      card.appendChild(h); card.appendChild(t); card.appendChild(p); card.appendChild(b);
      d.appendChild(card);
      document.body.appendChild(d);
    } catch (e) {}
  }

  function toast(msg) {
    try {
      var id = 'swg-warn', old = document.getElementById(id);
      if (old) old.remove();
      var d = document.createElement('div');
      d.id = id;
      d.setAttribute('style',
        'position:fixed;left:50%;transform:translateX(-50%);bottom:24px;z-index:2147483646;' +
        'background:#7c2d12;color:#fff;border:1px solid #c2410c;padding:12px 18px;' +
        'border-radius:12px;font-family:system-ui,sans-serif;font-size:13.5px;max-width:88vw');
      d.textContent = msg;
      document.body.appendChild(d);
      setTimeout(function () { try { d.remove(); } catch (e) {} }, 8000);
    } catch (e) {}
  }

  function ping(force) {
    var now = Date.now();
    if (!force && now - lastPing < PING_MS) return;
    lastPing = now;
    try {
      firebase.app().functions('asia-south1')
        .httpsCallable('sessionPing')({ sid: sid })
        .catch(function (err) {
          var m = String((err && err.message) || '');
          if (m.indexOf('SESSION_KHATAM:') >= 0) {
            kill(m.split('SESSION_KHATAM:')[1].trim());
          }
          // बाक़ी ग़लतियाँ (नेटवर्क टूटना वग़ैरह) चुपचाप छोड़ो — वरना
          // ट्रेन में नेटवर्क जाते ही ग्राहक लॉगआउट हो जाएगा.
        });
    } catch (e) {}
  }

  function onTick() {
    if (dying) return;
    var idle = Date.now() - lastAct;

    if (idle >= IDLE_MS) return kill('nishkriya');

    if (idle >= IDLE_MS - WARN_MS && !warned) {
      warned = true;
      toast('⏳ आप काफ़ी देर से निष्क्रिय हैं — एक मिनट में अपने-आप logout हो जाएगा।');
    }
    if (idle < IDLE_MS - WARN_MS) warned = false;

    ping(false);
  }

  function activity() {
    lastAct = Date.now();
    if (warned) {
      warned = false;
      var w = document.getElementById('swg-warn');
      if (w) { try { w.remove(); } catch (e) {} }
    }
  }

  function watch(uid) {
    try {
      unsub = firebase.firestore().collection('security_sessions').doc(uid)
        .onSnapshot(function (snap) {
          var d = snap && snap.exists ? snap.data() : null;
          if (!d) return;
          if (d.revoked === true) return kill(d.reason || 'revoked');
          // दूसरी जगह नया login हुआ → यह पुराना tab बाहर
          if (d.sid && sid && d.sid !== sid) return kill('device-badla');
        }, function () {
          // listener टूट गया (rules/नेटवर्क) — server से पूछ लो
          ping(true);
        });
    } catch (e) {}
  }

  function stop() {
    if (unsub) { try { unsub(); } catch (e) {} unsub = null; }
    if (tick) { clearInterval(tick); tick = null; }
  }

  function start(user) {
    if (started || !user) return;
    started = true; dying = false;
    sid = newSid();
    lastAct = Date.now();
    lastPing = 0;
    ping(true);         // पहला ping तुरंत — session दर्ज हो जाए
    watch(user.uid);
    tick = setInterval(onTick, TICK_MS);

    ['click', 'keydown', 'touchstart', 'scroll', 'mousemove'].forEach(function (ev) {
      document.addEventListener(ev, activity, { passive: true, capture: true });
    });
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) { activity(); ping(true); }
    });
  }

  try {
    firebase.auth().onAuthStateChanged(function (u) {
      if (u) start(u);
      else { started = false; stop(); }
    });
  } catch (e) {}

  window.SWGuard = {
    get sid() { return sid; },
    get alive() { return !dying && started; },
    idleMs: function () { return Date.now() - lastAct; },
    ping: function () { ping(true); },
    _judgeLocal: function (d, mySid) {     // टेस्ट के लिए
      if (!d) return 'ok';
      if (d.revoked === true) return 'kill:' + (d.reason || 'revoked');
      if (d.sid && mySid && d.sid !== mySid) return 'kill:device-badla';
      return 'ok';
    }
  };
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 4 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([4, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 5 ═══ जान-बूझकर नहीं लपेटा: इसके top-level
   let/const दूसरे ब्लॉक इस्तेमाल करते हैं, और try{} के अंदर
   वे इसी ब्लॉक तक सिमट जाते. */
const firebaseConfig = {
      apiKey: "AIzaSyA4kInzUxzF6Or1sHfzXavx1nVM0x40lak",
      authDomain: "sewaastra.firebaseapp.com",
      projectId: "sewaastra",
      storageBucket: "sewaastra.firebasestorage.app",
      messagingSenderId: "211091351218",
      appId: "1:211091351218:web:5602f5f1a36a21c3464bab",
      measurementId: "G-52QKXTC1J4"
  };

  if (!firebase.apps.length) {
      firebase.initializeApp(firebaseConfig);
      try{ if(firebase.analytics) firebase.analytics(); }catch(e){}
  }

  const db = null; /* RTDB unused - removed for speed */
  const firestore = firebase.firestore();

  let cart = [];
  let selectedMode = "";
  let currentIssue = "";
  let currentLang = 'hi';
  let mapInstance = null;
  let markerInstance = null;
  let trackingMapInstance = null;
  let trackingMarkerInstance = null;
  let userCoords = { lat: 23.2599, lon: 77.4126 };
  let appliedDiscount = 0;
  let windowConfirmationResult = null;
  let deferredPrompt = null;

  function showLoader(text = "कृपया प्रतीक्षा करें...") {
      document.getElementById('loaderText').innerText = text;
      document.getElementById('globalLoaderOverlay').style.display = 'flex';
  }
  function hideLoader() {
      document.getElementById('globalLoaderOverlay').style.display = 'none';
  }

  let categoriesData = JSON.parse(localStorage.getItem('sw_custom_categories')) || [
      { key: 'mobile', name: 'Mobile', icon: 'fa-mobile-alt' },
      { key: 'ac', name: 'AC Service', icon: 'fa-wind' },
      { key: 'fridge', name: 'Fridge', icon: 'fa-snowflake' },
      { key: 'wm', name: 'Washing', icon: 'fa-tint' },
      { key: 'tv', name: 'Smart TV', icon: 'fa-tv' },
      { key: 'elec', name: 'Electrician', icon: 'fa-bolt' },
      { key: 'plumbing', name: 'Plumber', icon: 'fa-wrench' }
  ];

  let mainData = JSON.parse(localStorage.getItem('sw_custom_services')) || {
      'mobile': [
          {
              n: 'Broken Screen Repair', p: 999, i: 'https://images.unsplash.com/photo-1512428559087-560fa5ceab42?w=200',
              subOptions: ['Original Glass Replacement (+₹500)', 'Tempered Glass Guard (+₹150)', 'Touch Panel Fix (+₹300)']
          },
          {
              n: 'Battery Replacement', p: 899, i: 'https://images.unsplash.com/photo-1583863788434-e58a36330cf0?w=200',
              subOptions: ['High Backup Battery (+₹300)', 'Standard Battery (+₹0)']
          }
      ],
      'ac': [
          {
              n: 'AC Deep Cleaning', p: 499, i: 'https://images.unsplash.com/photo-1621905251189-08b45d6a269e?w=200',
              subOptions: ['Foam Jet Technology (+₹150)', 'Anti-Bacterial Coil Treatment (+₹100)']
          }
      ],
      'fridge': [
          {
              n: 'Not Cooling Repair', p: 399, i: 'https://images.unsplash.com/photo-1584622650111-993a426fbf0a?w=200',
              subOptions: ['Thermostat Replacement (+₹350)', 'Defrost Timer Fix (+₹250)']
          }
      ],
      'wm': [
          {
              n: 'Drainage Issue Fix', p: 299, i: 'https://images.unsplash.com/photo-1626806787461-102c1bfaaea1?w=200',
              subOptions: ['Drain Pump Replacement (+₹400)', 'Pipe Blockage Clear (+₹0)']
          }
      ],
      'tv': [
          {
              n: 'LED Wall Mount', p: 249, i: 'https://images.unsplash.com/photo-1593784991095-a205069470b6?w=200',
              subOptions: ['Heavy-Duty Bracket (+₹150)', 'Standard Movable Stand (+₹0)']
          }
      ],
      'elec': [
          {
              n: 'New Point Fitting', p: 149, i: 'https://images.unsplash.com/photo-1621905251918-48416bd8575a?w=200',
              subOptions: ['Concealed Wiring (+₹100)', 'Surface PVC Channel (+₹0)']
          }
      ],
      'plumbing': [
          {
              n: 'Pipe Leakage Repair', p: 199, i: 'https://images.unsplash.com/photo-1542013936693-84d72044ffc2?w=200',
              subOptions: ['PVC Pipe Replacement (+₹150)', 'CPVC Joint Seal (+₹100)']
          }
      ]
  };

  let bannersData = JSON.parse(localStorage.getItem('sw_custom_banners')) || [
      { title: "🎉 पहली बुकिंग पर 50% छूट", desc: "कूपन कोड: SEWA50 का उपयोग करें", bg: "" },
      { title: "🛡️ 100% वेरिफाइड एक्सपर्ट्स", desc: "सुरक्षित और पेशेवर होम सर्विस", bg: "linear-gradient(135deg, #43cea2, #185a9d)" }
  ];

  let couponsData = JSON.parse(localStorage.getItem('sw_custom_coupons')) || {
      "SEWA50": 50,
      "SEWA100": 100
  };

  const LANG_DATA = {
    hi: { home:"होम", support:"सहायता", history:"इतिहास", noHistory:"कोई इतिहास नहीं मिला" },
    en: { home:"Home", support:"Support", history:"History", noHistory:"No history found" },
  };

  function showAlert(title, message) {
      hideLoader();
      document.getElementById('customAlertTitle').innerText = title;
      document.getElementById('customAlertMsg').innerHTML = message;
      document.getElementById('customAlertOverlay').style.display = 'flex';
  }
  function closeCustomAlert() {
      document.getElementById('customAlertOverlay').style.display = 'none';
  }

  // --- CONDITIONAL APP INSTALL MODAL ---
  window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
  });

  function checkAndShowInstallModalAfterLogin() {
      let isInstalledDismissed = localStorage.getItem('sw_install_dismissed');
      if (!isInstalledDismissed) {
          setTimeout(() => {
              document.getElementById('installAppModal').style.display = 'flex';
          }, 1000);
      }
  }

  function triggerAppInstall() {
      document.getElementById('installAppModal').style.display = 'none';
      localStorage.setItem('sw_install_dismissed', 'true');
      if (deferredPrompt) {
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then((choiceResult) => {
              if (choiceResult.outcome === 'accepted') {
                  showToast("SewaAstra ऐप इनस्टॉल हो रहा है! 🎉");
              }
              deferredPrompt = null;
          });
      } else {
          showAlert("ऐप इनस्टॉल करें", "अपने ब्राउज़र मेनू (⋮) से <b>'Add to Home Screen'</b> या <b>'Install App'</b> पर क्लिक करें ताकि आप ऐप की तरह इसका उपयोग कर सकें!");
      }
  }

  function closeInstallModal() {
      document.getElementById('installAppModal').style.display = 'none';
      localStorage.setItem('sw_install_dismissed', 'true');
  }

  function checkAdminAccess(identifier) {
      /* 🔒 C-1: सिर्फ server-issued custom claim. localStorage/email string compare नहीं. */
      var ok = false;
      try{ ok = !!(window.SWSec && window.SWSec.isAdmin); }catch(e){}
      var adminBtn = document.getElementById('adminPanelMenuBtn');
      if(adminBtn){ adminBtn.setAttribute('data-admin-only',''); adminBtn.style.display = ok ? 'flex' : 'none'; }
      return ok;
  }

  function renderCategoriesGrid() {
      let grid = document.getElementById('catGridArea');
      grid.innerHTML = "";
      let displayLimit = 7;
      let visibleCats = categoriesData.slice(0, displayLimit);

      visibleCats.forEach(cat => {
          grid.innerHTML += `
              <div class="cat-item" onclick="load('${SWSec.esc(String(cat.key||'').replace(/[^A-Za-z0-9_-]/g,''))}', this)">
                  <div class="cat-icon"><i class="fa ${SWSec.esc(String(cat.icon||'').replace(/[^A-Za-z0-9 _-]/g,''))}"></i></div>
                  <span>${SWSec.esc(cat.name)}</span>
              </div>`;
      });

      grid.innerHTML += `
          <div class="cat-item" onclick="toggleMoreSheet()">
              <div class="cat-icon" style="background: var(--primary); color: white;"><i class="fa fa-ellipsis-h" style="color:white;"></i></div>
              <span>More</span>
          </div>`;
  }

  function toggleMoreSheet() {
      let overlay = document.getElementById('moreOverlay');
      overlay.style.display = (overlay.style.display === 'flex') ? 'none' : 'flex';
      if (overlay.style.display === 'flex') {
          renderMoreCategoriesGrid();
      }
  }

  function closeMoreSheet(e) {
      if(!e || e.target.id === 'moreOverlay') {
          document.getElementById('moreOverlay').style.display = 'none';
      }
  }

  function renderMoreCategoriesGrid() {
      let moreGrid = document.getElementById('moreCategoriesGridArea');
      moreGrid.innerHTML = "";
      categoriesData.forEach(cat => {
          moreGrid.innerHTML += `
              <div class="cat-item" onclick="toggleMoreSheet(); load('${cat.key}', this);" style="background:var(--bg); padding:12px; border-radius:15px; border:1px solid #eee;">
                  <div class="cat-icon" style="width:50px; height:50px;"><i class="fa ${cat.icon}" style="font-size:20px;"></i></div>
                  <span style="font-size:12px; margin-top:5px;">${SWXSS.esc(cat.name)}</span>
              </div>`;
      });
  }

  function renderBanners() {
      let carousel = document.getElementById('bannerCarouselArea');
      carousel.innerHTML = "";
      bannersData.forEach(b => {
          let bgStyle = b.bg ? `background: ${b.bg};` : `background: linear-gradient(135deg, #ff8008, #ffc837);`;
          if(b.bg && b.bg.startsWith('http')) {
              bgStyle = `background-image: url('${b.bg}');`;
          }
          carousel.innerHTML += `
              <div class="banner-card" style="${bgStyle}">
                  <h3>${SWXSS.esc(b.title)}</h3>
                  <p>${SWXSS.esc(b.desc)}</p>
              </div>`;
      });
  }

  function openAdminPanel() {
      document.getElementById('adminModal').style.display = 'flex';
      toggleProfile();
      populateAdminCatDropdown();
      populateAdminServiceDropdown();
      populateAdminBannerDropdown();
      renderAdminCouponsList();
      renderAdminCategoriesList();
  }
  function closeAdminPanel() {
      document.getElementById('adminModal').style.display = 'none';
  }

  function switchAdminTab(tab) {
      document.getElementById('adminSecServices').style.display = tab === 'services' ? 'block' : 'none';
      document.getElementById('adminSecCategories').style.display = tab === 'categories' ? 'block' : 'none';
      document.getElementById('adminSecBanners').style.display = tab === 'banners' ? 'block' : 'none';
      document.getElementById('adminSecCoupons').style.display = tab === 'coupons' ? 'block' : 'none';
      
      document.getElementById('admTabServBtn').style.background = tab === 'services' ? 'var(--primary)' : 'transparent';
      document.getElementById('admTabServBtn').style.color = tab === 'services' ? 'white' : '#555';
      document.getElementById('admTabCatBtn').style.background = tab === 'categories' ? 'var(--primary)' : 'transparent';
      document.getElementById('admTabCatBtn').style.color = tab === 'categories' ? 'white' : '#555';
      document.getElementById('admTabBannerBtn').style.background = tab === 'banners' ? 'var(--primary)' : 'transparent';
      document.getElementById('admTabBannerBtn').style.color = tab === 'banners' ? 'white' : '#555';
      document.getElementById('admTabCouponBtn').style.background = tab === 'coupons' ? 'var(--primary)' : 'transparent';
      document.getElementById('admTabCouponBtn').style.color = tab === 'coupons' ? 'white' : '#555';
  }

  function populateAdminCatDropdown() {
      let select = document.getElementById('adminCatSelect');
      select.innerHTML = "";
      categoriesData.forEach(c => {
          select.innerHTML += `<option value="${c.key}">${SWSec.esc(c.name)}</option>`;
      });
  }

  function populateAdminServiceDropdown() {
      let cat = document.getElementById('adminCatSelect').value;
      let serviceSelect = document.getElementById('adminServiceSelect');
      serviceSelect.innerHTML = `<option value="NEW">-- नई सर्विस जोड़ें (New Service) --</option>`;
      if(mainData[cat]) {
          mainData[cat].forEach((s, idx) => {
              serviceSelect.innerHTML += `<option value="${idx}">${SWSec.esc(s.n)} (₹${Number(s.p)||0})</option>`;
          });
      }
      clearAdminServiceForm();
  }

  function clearAdminServiceForm() {
      document.getElementById('adminServiceName').value = "";
      document.getElementById('adminServicePrice').value = "";
      document.getElementById('adminServiceImage').value = "";
      document.getElementById('adminSubOptions').value = "";
  }

  function loadServiceDataIntoForm() {
      let cat = document.getElementById('adminCatSelect').value;
      let idx = document.getElementById('adminServiceSelect').value;
      if(idx === "NEW") { clearAdminServiceForm(); return; }
      let service = mainData[cat][idx];
      if(service) {
          document.getElementById('adminServiceName').value = service.n;
          document.getElementById('adminServicePrice').value = service.p;
          document.getElementById('adminServiceImage').value = service.i;
          document.getElementById('adminSubOptions').value = service.subOptions ? service.subOptions.join(', ') : "";
      }
  }

  function convertAdminImageToUrl(input, targetInputId) {
      if (input.files && input.files[0]) {
          const reader = new FileReader();
          reader.onload = function(e) {
              document.getElementById(targetInputId).value = e.target.result;
              showToast("फोटो सफलतापूर्वक लोड हो गई! 🖼️");
          }
          reader.readAsDataURL(input.files[0]);
      }
  }

  function saveAdminServiceChanges() {
      let cat = document.getElementById('adminCatSelect').value;
      let idx = document.getElementById('adminServiceSelect').value;
      let name = document.getElementById('adminServiceName').value.trim();
      let price = Number(document.getElementById('adminServicePrice').value);
      let img = document.getElementById('adminServiceImage').value.trim() || 'https://images.unsplash.com/photo-1581092160607-ee22621dd758?w=200';
      let subOptsRaw = document.getElementById('adminSubOptions').value.trim();
      let subOptionsArr = subOptsRaw ? subOptsRaw.split(',').map(s => s.trim()) : ['Standard Option (+₹0)'];

      if(!name || !price) return showAlert("त्रुटि", "कृपया सर्विस का नाम और कीमत सही भरें");
      if(!mainData[cat]) mainData[cat] = [];

      if(idx === "NEW") {
          mainData[cat].push({ n: name, p: price, i: img, subOptions: subOptionsArr });
          showAlert("सफलता", "नई सर्विस सफलतापूर्वक जोड़ दी गई! 🎉");
      } else {
          mainData[cat][idx] = { n: name, p: price, i: img, subOptions: subOptionsArr };
          showAlert("सफलता", "सर्विस सफलतापूर्वक अपडेट कर दी गई! ✅");
      }

      localStorage.setItem('sw_custom_services', JSON.stringify(mainData));
      closeAdminPanel();
      load(cat);
  }

  function saveAdminCategory() {
      let key = document.getElementById('adminNewCatKey').value.trim().toLowerCase();
      let name = document.getElementById('adminNewCatName').value.trim();
      let icon = document.getElementById('adminNewCatIcon').value.trim() || 'fa-concierge-bell';

      if(!key || !name) return showAlert("त्रुटि", "कृपया कैटेगरी की कुंजी और नाम दर्ज करें");

      if(categoriesData.some(c => c.key === key)) {
          return showAlert("त्रुटि", "यह कैटेगरी की कुंजी पहले से मौजूद है!");
      }

      categoriesData.push({ key, name, icon });
      if(!mainData[key]) mainData[key] = [];

      localStorage.setItem('sw_custom_categories', JSON.stringify(categoriesData));
      localStorage.setItem('sw_custom_services', JSON.stringify(mainData));

      showAlert("सफलता", `नई कैटेगरी '${name}' सफलतापूर्वक जोड़ दी गई! 🎉`);
      renderCategoriesGrid();
      populateAdminCatDropdown();
      renderAdminCategoriesList();
      document.getElementById('adminNewCatKey').value = "";
      document.getElementById('adminNewCatName').value = "";
      document.getElementById('adminNewCatIcon').value = "";
  }

  function deleteAdminCategory(key) {
      swUi.confirm({icon:'🗑️',title:'कैटेगरी हटाएँ?',msg:`क्या आप वाकई कैटेगरी '${key}' और उसके अंतर्गत सभी सर्विसेज को हटाना चाहते हैं?`,ok:'हाँ, हटाएँ',cancel:'रुकें',danger:true,onOk:function(){
          categoriesData = categoriesData.filter(c => c.key !== key);
          delete mainData[key];
          localStorage.setItem('sw_custom_categories', JSON.stringify(categoriesData));
          localStorage.setItem('sw_custom_services', JSON.stringify(mainData));
          renderCategoriesGrid();
          populateAdminCatDropdown();
          renderAdminCategoriesList();
          showToast("कैटेगरी सफलतापूर्वक हटा दी गई!");
      }});
  }

  function renderAdminCategoriesList() {
      let listDiv = document.getElementById('adminCategoriesList');
      let html = `<b>मौजूदा कैटेगरी लिस्ट (हटाने का विकल्प):</b><br><br>`;
      categoriesData.forEach(c => {
          html += `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; background:#f9f9f9; padding:6px 10px; border-radius:8px;">
              <span>[${c.key}] <b>${c.name}</b></span>
              <button onclick="deleteAdminCategory('${c.key}')" style="background:#ff3b30; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer; font-size:11px; width:auto; margin:0;">हटाएं (Delete)</button>
          </div>`;
      });
      listDiv.innerHTML = html;
  }

  function populateAdminBannerDropdown() {
      let bannerSelect = document.getElementById('adminBannerSelect');
      bannerSelect.innerHTML = `<option value="NEW">-- नया बैनर जोड़ें (New Banner) --</option>`;
      bannersData.forEach((b, idx) => {
          bannerSelect.innerHTML += `<option value="${idx}">बैनर #${idx+1}: ${SWSec.esc(b.title)}</option>`;
      });
      clearAdminBannerForm();
  }

  function clearAdminBannerForm() {
      document.getElementById('adminBannerTitle').value = "";
      document.getElementById('adminBannerDesc').value = "";
      document.getElementById('adminBannerBg').value = "";
  }

  function loadBannerDataIntoForm() {
      let idx = document.getElementById('adminBannerSelect').value;
      if(idx === "NEW") { clearAdminBannerForm(); return; }
      let banner = bannersData[idx];
      if(banner) {
          document.getElementById('adminBannerTitle').value = banner.title;
          document.getElementById('adminBannerDesc').value = banner.desc;
          document.getElementById('adminBannerBg').value = banner.bg || "";
      }
  }

  function saveAdminBannerChanges() {
      let idx = document.getElementById('adminBannerSelect').value;
      let title = document.getElementById('adminBannerTitle').value.trim();
      let desc = document.getElementById('adminBannerDesc').value.trim();
      let bg = document.getElementById('adminBannerBg').value.trim();

      if(!title) return showAlert("त्रुटि", "कृपया बैनर शीर्षक दर्ज करें");

      if(idx === "NEW") {
          bannersData.push({ title, desc, bg });
          showAlert("सफलता", "नया बैनर जोड़ दिया गया! 🎉");
      } else {
          bannersData[idx] = { title, desc, bg };
          showAlert("सफलता", "बैनर अपडेट हो गया! ✅");
      }

      localStorage.setItem('sw_custom_banners', JSON.stringify(bannersData));
      renderBanners();
      closeAdminPanel();
  }

  function saveAdminCouponChanges() {
      let code = document.getElementById('adminCouponCode').value.trim().toUpperCase();
      let discount = Number(document.getElementById('adminCouponDiscount').value);

      if(!code || !discount) return showAlert("त्रुटि", "कृपया कूपन कोड और छूट राशि सही भरें");

      couponsData[code] = discount;
      localStorage.setItem('sw_custom_coupons', JSON.stringify(couponsData));
      showAlert("सफलता", `कूपन ${code} (₹${discount} छूट) सफलतापूर्वक सेव हो गया! 🎟️`);
      renderAdminCouponsList();
      document.getElementById('adminCouponCode').value = "";
      document.getElementById('adminCouponDiscount').value = "";
  }

  function renderAdminCouponsList() {
      let listDiv = document.getElementById('adminCouponsList');
      let html = `<b>सक्रिय कूपन लिस्ट:</b><br>`;
      for(let c in couponsData) {
          html += `- Code: <b>${c}</b> (₹${couponsData[c]} Off)<br>`;
      }
      listDiv.innerHTML = html;
  }

  // --- GOOGLE & PHONE LOGIN ---
  function swGoogleDone(result) {
      var __prev=''; try{ __prev=localStorage.getItem('sw_user')||''; }catch(e){}
      hideLoader();
      const user = result.user;
      localStorage.setItem('sw_logged', 'true');
      const identifier = user.email || user.phoneNumber || "Google User";
      localStorage.setItem('sw_user', identifier);
      checkAdminAccess(user.email || "");
      if(user.photoURL) {
          localStorage.setItem('sw_user_photo', user.photoURL);
          document.getElementById('headerPic').src = user.photoURL;
          document.getElementById('sheetPic').src = user.photoURL;
      }
      document.getElementById('authOverlay').style.display = 'none';
      if(/^\d{10}$/.test(__prev)){ document.getElementById('googlePhonePromptOverlay').style.display = 'none'; try{ showToast('👋 वापसी पर स्वागत! एक-टैप login ✅'); }catch(e){} } else { document.getElementById('googlePhonePromptOverlay').style.display = 'flex'; }
      checkAndShowInstallModalAfterLogin();
      showToast("Google से लॉगिन सफल! अब मोबाइल नंबर दर्ज करें।");
  }
  function swGoogleFail(error) {
      hideLoader();
      var cd = (error && error.code) || '';
      if(['auth/popup-blocked','auth/operation-not-supported-in-this-environment','auth/web-storage-unsupported','auth/popup-closed-by-user','auth/internal-error'].indexOf(cd) > -1) {
          try {
              showToast("Redirect से login हो रहा है...");
              const provider2 = new firebase.auth.GoogleAuthProvider();
              firebase.auth().signInWithRedirect(provider2);
              return;
          } catch(e2) {}
      }
      showAlert("लॉगिन त्रुटि", (error && error.message) || error);
  }
  function swInApk() {
      try { if(window.SewaApp && window.SewaApp.isApp && window.SewaApp.isApp()) return true; } catch(e) {}
      return false;
  }
  function loginWithGoogle() {
      showLoader("Google से लॉगिन हो रहा है...");
      const provider = new firebase.auth.GoogleAuthProvider();
      try {
          if(swInApk()) { firebase.auth().signInWithRedirect(provider); return; }
      } catch(e) {}
      firebase.auth().signInWithPopup(provider).then(swGoogleDone).catch(swGoogleFail);
  }
  /* v16 — APK redirect se wapas aane par login poora karo */
  window.addEventListener('load', function() {
      setTimeout(function() {
          try {
              if(!swInApk()) return;
              if(!(window.firebase && firebase.auth)) return;
              firebase.auth().getRedirectResult().then(function(r) {
                  if(r && r.user) { try { swGoogleDone(r); } catch(e) {} }
              }).catch(function() {});
          } catch(e) {}
      }, 1200);
  });

  function submitGoogleLinkedPhone() {
      let phoneInput = document.getElementById('googleLinkedPhone').value.trim();
      if(phoneInput.length !== 10) {
          return showAlert("अमान्य नंबर", "कृपया सही 10-अंकों का मोबाइल नंबर दर्ज करें");
      }
      localStorage.setItem('sw_user', phoneInput);
      document.getElementById('profilePhoneDisplay').innerText = "+91 " + phoneInput;
      checkAdminAccess(phoneInput);
      document.getElementById('googlePhonePromptOverlay').style.display = 'none';
      fetchCityNameByGPS();
      showToast("मोबाइल नंबर सफलतापूर्वक लिंक हो गया!");
  }

  window.addEventListener('load', function() {
      if (!window.recaptchaVerifier) {
          try {
              window.recaptchaVerifier = new firebase.auth.RecaptchaVerifier('recaptcha-container', {
                  'size': 'invisible',
                  'callback': (response) => {}
              });
          } catch(e) { console.log(e); }
      }
  });

  function sendRealPhoneOTP() {
      let phoneInput = document.getElementById('userPhone').value.trim();
      if(phoneInput.length !== 10) {
          return showAlert("अमान्य नंबर", "कृपया सही 10-अंकों का मोबाइल नंबर दर्ज करें");
      }
      let phoneNumber = "+91" + phoneInput;
      let appVerifier = window.recaptchaVerifier;

      showLoader("OTP भेजा जा रहा है...");

      firebase.auth().signInWithPhoneNumber(phoneNumber, appVerifier)
          .then((confirmationResult) => {
              hideLoader();
              windowConfirmationResult = confirmationResult;
              localStorage.setItem('sw_user', phoneInput);
              document.getElementById('profilePhoneDisplay').innerText = phoneNumber;
              document.getElementById('phoneAuthSection').style.display = 'none';
              document.getElementById('otpAuthSection').style.display = 'block';
              showToast("मोबाइल पर असली OTP भेज दिया गया है! 📩");
          }).catch((error) => {
              hideLoader();
              console.error(error);
              showAlert("SMS OTP त्रुटि", error.message);
          });
  }

  function verifyRealPhoneOTP() {
      let otpCode = document.getElementById('userOTP').value.trim();
      if(otpCode.length !== 6) {
          return showAlert("अमान्य OTP", "कृपया 6-अंकों का सही OTP दर्ज करें");
      }

      showLoader("OTP सत्यापित हो रहा है...");

      if(windowConfirmationResult) {
          windowConfirmationResult.confirm(otpCode).then((result) => {
              hideLoader();
              const user = result.user;
              localStorage.setItem('sw_logged', 'true');
              let phone = localStorage.getItem('sw_user');
              checkAdminAccess(phone);
              document.getElementById('authOverlay').style.display = 'none';
              fetchCityNameByGPS();
              checkAndShowInstallModalAfterLogin();
              showToast("फोन नंबर सत्यापित और लॉगिन सफल! 🎉");
          }).catch((error) => {
              hideLoader();
              showAlert("सत्यापन विफल", "दर्ज किया गया OTP गलत है। कृपया पुनः प्रयास करें।");
          });
      } else {
          hideLoader();
          showAlert("त्रुटि", "कृपया पहले OTP अनुरोध करें।");
      }
  }

  function resetAuth() {
      document.getElementById('phoneAuthSection').style.display = 'block';
      document.getElementById('otpAuthSection').style.display = 'none';
  }

  function logoutNow() {
      firebase.auth().signOut();
      localStorage.removeItem('sw_logged');
      localStorage.removeItem('sw_is_admin');
      try{if(window.__exitGuard)window.__exitGuard.silent();}catch(_e){}location.reload();
  }
  function logout() {
      try{
        if(window.__exitGuard && window.__exitGuard.confirmExit){
          window.__exitGuard.confirmExit({
            icon:'🔓',
            title:'Logout करें?',
            sub:'क्या आप अपने <b>SewaAstra account</b> से logout करना चाहते हैं?<br>आपके ऑर्डर व wallet account में सुरक्षित रहेंगे — फिर से login करके देख सकते हैं।',
            yes:'हाँ, Logout',
            no:'रुकें',
            cb:function(){ logoutNow(); }
          });
          return;
        }
      }catch(e){}
      logoutNow();
  }

  // --- 10+ CUSTOMER REQUIREMENTS HANDLER FUNCTION ---
  function custReqAction(type) {
      toggleProfile();
      if (type === 'Wallet') {
          showAlert("SewaAstra Wallet", "आपके वॉलेट में वर्तमान बैलेंस: <b>₹250</b> (कैशबैक पॉइंट्स उपलब्ध)");
      } else if (type === 'Coupons') {
          showAlert("Active Discount Coupons", "1. <b>SEWA50</b>: ₹50 Off<br>2. <b>SEWA100</b>: ₹100 Off<br>3. <b>WELCOME20</b>: 20% Off");
      } else if (type === 'Addresses') {
          let addr = document.getElementById('manualAddr').value || "कोई सहेजा गया पता नहीं है।";
          showAlert("Saved Delivery Addresses", `डिफ़ॉल्ट पता: <br><b>${addr}</b>`);
      } else if (type === 'Notifications') {
          showAlert("Push Notifications", "बुकिंग अपडेट और ऑफर्स के लिए पुश नोटिफिकेशन्स वर्तमान में <b>सक्रिय (Active)</b> हैं।");
      } else if (type === 'Favorites') {
          showAlert("Favorite Services", "आपके पसंदीदा सर्विसेज:<br>• Broken Screen Repair<br>• AC Deep Cleaning");
      } else if (type === 'Referral') {
          showAlert("Refer & Earn", "अपने दोस्तों को SewaAstra शेयर करें और प्रत्येक सफल बुकिंग पर <b>₹100</b> प्राप्त करें!<br><br>आपका रेफरल कोड: <b>SEWA100REF</b>");
      } else if (type === 'Safety') {
          showAlert("Safety & Hygiene Guidelines", "हमारे सभी सर्विस पार्टनर्स वैक्सिनेटेड हैं, मास्क पहनते हैं और हर काम से पहले सैनिटाइजेशन सुनिश्चित करते हैं। 🛡️");
      } else if (type === 'Partner') {
          window.open("https://soorshyamvishwakarma37-cyber.github.io/Sewaastra-partner/", "_blank", 'noopener,noreferrer');
      } else if (type === 'Feedback') {
          showAlert("Rate App", "SewaAstra को 5-स्टार रेटिंग देने के लिए धन्यवाद! ⭐⭐⭐⭐⭐");
      } else if (type === 'TandC') {
          swLegal('terms');
      }
  }

  function filterServices() {
      let query = document.getElementById('srch').value.toLowerCase().trim();
      let display = document.getElementById('display');
      display.innerHTML = '';
      document.getElementById('catTitle').innerText = query ? `Search Results for "${query}"` : "Top Recommended Services";

      if (!query) {
          load(categoriesData[0].key);
          return;
      }

      let foundAny = false;
      for (let catKey in mainData) {
          mainData[catKey].forEach((s, idx) => {
              if (s.n.toLowerCase().includes(query) || catKey.toLowerCase().includes(query)) {
                  display.innerHTML += createCard(s, catKey + '_' + idx);
                  foundAny = true;
              }
          });
      }

      if (!foundAny) {
          display.innerHTML = `<div style="text-align:center; padding:40px; color:#888;">कोई सर्विस नहीं मिली। एडमिन पैनल से नई सर्विस जोड़ें।</div>`;
      }
  }

  function fetchCityNameByGPS() {
      if (navigator.geolocation) {
          navigator.geolocation.getCurrentPosition((position) => {
              userCoords.lat = position.coords.latitude;
              userCoords.lon = position.coords.longitude;
              let mapsLink = `https://www.google.com/maps?q=${userCoords.lat},${userCoords.lon}`;
              document.getElementById('googleMapsLink').value = mapsLink;
              
              fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${userCoords.lat}&lon=${userCoords.lon}`)
                  .then(response => response.json())
                  .then(data => {
                      let cityName = data.address.city || data.address.town || data.address.village || data.address.suburb || "Current Location";
                      document.getElementById('locTxt').innerText = cityName;
                      document.getElementById('manualAddr').value = `${cityName} (${userCoords.lat.toFixed(3)}, ${userCoords.lon.toFixed(3)})`;
                  })
                  .catch(() => {
                      document.getElementById('locTxt').innerText = "GPS Set ✅";
                      document.getElementById('manualAddr').value = `GPS Live Location (${userCoords.lat.toFixed(3)}, ${userCoords.lon.toFixed(3)})`;
                  });
          }, (error) => {
              console.log("Auto GPS error:", error);
          }, { timeout: 10000, enableHighAccuracy: true });
      }
  }

  function getLiveLocation() {
      showLoader("लोकेशन प्राप्त की जा रही है...");
      if (navigator.geolocation) {
          navigator.geolocation.getCurrentPosition((position) => {
              hideLoader();
              userCoords.lat = position.coords.latitude;
              userCoords.lon = position.coords.longitude;
              let mapsLink = `https://www.google.com/maps?q=${userCoords.lat},${userCoords.lon}`;
              document.getElementById('googleMapsLink').value = mapsLink;
              
              fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${userCoords.lat}&lon=${userCoords.lon}`)
                  .then(response => response.json())
                  .then(data => {
                      let cityName = data.address.city || data.address.town || data.address.village || data.address.suburb || "Live Location";
                      document.getElementById('locTxt').innerText = cityName;
                      document.getElementById('manualAddr').value = `${cityName} (${userCoords.lat.toFixed(3)}, ${userCoords.lon.toFixed(3)})`;
                      showToast(`लोकेशन: ${cityName} सेट हो गई! 📍`);
                  })
                  .catch(() => {
                      document.getElementById('locTxt').innerText = "लोकेशन सेट ✅";
                      document.getElementById('manualAddr').value = `GPS Live Location (${userCoords.lat.toFixed(3)}, ${userCoords.lon.toFixed(3)})`;
                      showToast("GPS लोकेशन सफलतापूर्वक मिल गई! 📍");
                  });
          }, (error) => {
              hideLoader();
              showAlert("लोकेशन त्रुटि", "लोकेशन अनुमतियाँ अस्वीकृत या उपलब्ध नहीं हैं। कृपया मैप का उपयोग करें।");
              openMapModal();
          }, { timeout: 10000, enableHighAccuracy: true });
      } else {
          hideLoader();
          showAlert("असमर्थित", "आपका ब्राउज़र जिओलोकेशन सपोर्ट नहीं करता है।");
      }
  }

  function openMapModal() {
      document.getElementById('leafletMapModal').style.display = 'flex';
      setTimeout(() => {
          if (!mapInstance) {
              mapInstance = L.map('mapContainer').setView([userCoords.lat, userCoords.lon], 14);
              L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19 }).addTo(mapInstance);
              markerInstance = L.marker([userCoords.lat, userCoords.lon], { draggable: true }).addTo(mapInstance);
              markerInstance.on('dragend', function(e) {
                  userCoords.lat = e.target.getLatLng().lat;
                  userCoords.lon = e.target.getLatLng().lng;
              });
          } else { mapInstance.invalidateSize(); }
      }, 300);
  }

  function closeMapModal() { document.getElementById('leafletMapModal').style.display = 'none'; }

  function confirmMapLocation() {
      let mapsLink = `https://www.google.com/maps?q=${userCoords.lat},${userCoords.lon}`;
      document.getElementById('googleMapsLink').value = mapsLink;
      document.getElementById('manualAddr').value = `Map Pin: ${userCoords.lat.toFixed(4)}, ${userCoords.lon.toFixed(4)}`;
      document.getElementById('locTxt').innerText = "मैप सेट ✅";
      closeMapModal();
      showToast("मैप लोकेशन कन्फर्म हो गई!");
  }

  // --- LIVE TRACKING MODAL & INTERACTION ---
  function openLiveTracking(orderId) {
      document.getElementById('liveTrackingModal').style.display = 'flex';
      setTimeout(() => {
          if (!trackingMapInstance) {
              trackingMapInstance = L.map('trackingMapContainer').setView([userCoords.lat, userCoords.lon], 15);
              L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19 }).addTo(trackingMapInstance);
              trackingMarkerInstance = L.marker([userCoords.lat + 0.005, userCoords.lon + 0.005]).addTo(trackingMapInstance)
                  .bindPopup("<b>राहुल कुमार (Service Partner)</b><br>आपकी ओर आ रहे हैं").openPopup();
          } else {
              trackingMapInstance.invalidateSize();
          }
      }, 300);
  }

  function closeLiveTracking() {
      document.getElementById('liveTrackingModal').style.display = 'none';
  }

  function openMaskCall(oid){ try{ oid=String(oid||'').trim(); }catch(e){ oid=''; } try{ var S=window['SW'+'Agora']; if(S&&typeof S.dial==='function'){ if(oid){ S.dial(oid); return; } } }catch(e){} showAlert("Mask Calling", "Surakshit calling connect ho rahi hai..."); setTimeout(function(){ window.location.href = "tel:7869969190"; }, 1500);   }

  function openInAppChat() {
      document.getElementById('chatCallModal').style.display = 'flex';
  }

  function closeChatCallModal(e) {
      if(!e || e.target.id === 'chatCallModal') {
          document.getElementById('chatCallModal').style.display = 'none';
      }
  }

  function sendChatMessage() {
      let input = document.getElementById('chatInputMsg');
      let text = input.value.trim();
      if(!text) return;
      let container = document.getElementById('chatMsgContainer');
      container.innerHTML += `<div class="chat-bubble user">${SWSec.esc(text)}</div>`;
      input.value = "";
      container.scrollTop = container.scrollHeight;

      setTimeout(() => {
          container.innerHTML += `<div class="chat-bubble partner">ठीक है जी, नोट कर लिया है। जल्द पहुँचते हैं!</div>`;
          container.scrollTop = container.scrollHeight;
      }, 1200);
  }

  function setLang(lang, event) {
      currentLang = lang;
      localStorage.setItem("sw_lang", lang);
      document.querySelectorAll(".lang-btn").forEach(b => b.classList.remove("active"));
      if(event && event.currentTarget) event.currentTarget.classList.add("active");
      document.getElementById("navHome").innerHTML = `<i class="fa fa-home"></i>${LANG_DATA[lang].home}`;
      document.getElementById("navSupp").innerHTML = `<i class="fa fa-headset"></i>${LANG_DATA[lang].support}`;
      document.getElementById("navHis").innerHTML = `<i class="fa fa-history"></i>${LANG_DATA[lang].history}`;
      showToast("भाषा बदली गई!");
  }

  function triggerUpload() { document.getElementById('photoInput').click(); }

  function previewPhoto(input) {
      if (input.files && input.files[0]) {
          const reader = new FileReader();
          reader.onload = function(e) {
              localStorage.setItem('sw_user_photo', e.target.result);
              document.getElementById('headerPic').src = e.target.result;
              document.getElementById('sheetPic').src = e.target.result;
              showToast("प्रोफाइल फोटो अपडेट हो गई! 🖼️");
          }
          reader.readAsDataURL(input.files[0]);
      }
  }

  function shareApp() {
      if (navigator.share) {
          navigator.share({ title: 'SewaAstra', text: 'भारत की सबसे भरोसेमंद होम सर्विस ऐप!', url: 'https://soorshyamvishwakarma37-cyber.github.io/SewaAstra/' });
      } else { showAlert("शेयर लिंक", "लिंक कॉपी करें: <b>https://soorshyamvishwakarma37-cyber.github.io/SewaAstra/</b>"); }
  }

  function toggleDark() {
      document.body.classList.toggle('dark-mode');
      let isDark = document.body.classList.contains('dark-mode');
      localStorage.setItem('sw_dark', isDark);
      document.getElementById('darkBtn').checked = isDark;
  }

  function checkout() {
      if(cart.length === 0) return showAlert("कार्ट खाली है", "कृपया पहले कोई सर्विस जोड़ें");
      document.getElementById('fullCartPanel').style.display = 'flex';
      setDefaultDateTime();
      renderCart();
      renderCheckoutCouponsList();
  }

  function closeCart(e) {
      if(!e || e.target.id === 'fullCartPanel') { document.getElementById('fullCartPanel').style.display = 'none'; }
  }

  function setDefaultDateTime() {
      const now = new Date();
      document.getElementById('cartDate').value = now.toISOString().split('T')[0];
      document.getElementById('cartTime').value = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
  }

  function renderCheckoutCouponsList() {
      let container = document.getElementById('availableCouponsContainer');
      container.innerHTML = "";
      for(let code in couponsData) {
          container.innerHTML += `
              <button type="button" onclick="selectAndApplyCoupon('${code}')" style="background:var(--primary-light); color:var(--primary); border:1px solid var(--primary); padding:6px 12px; border-radius:8px; font-weight:bold; font-size:12px; white-space:nowrap; cursor:pointer;">
                  🏷️ ${code} (₹${couponsData[code]} Off)
              </button>`;
      }
  }

  function selectAndApplyCoupon(code) {
      document.getElementById('couponInput').value = code;
      applyCoupon();
  }

  function applyCoupon() {
      let code = document.getElementById('couponInput').value.trim().toUpperCase();
      if(couponsData[code] !== undefined) {
          appliedDiscount = couponsData[code];
          document.getElementById('couponMsg').style.color = "green";
          document.getElementById('couponMsg').innerText = `कूपन सफल! ₹${appliedDiscount} की छूट लागू हो गई है ✅`;
          renderCart();
      } else {
          appliedDiscount = 0;
          document.getElementById('couponMsg').style.color = "red";
          document.getElementById('couponMsg').innerText = "अमान्य कूपन कोड";
          renderCart();
      }
  }

  function renderCart() {
      let list = document.getElementById('cartItemsList');
      let subtotal = 0;
      list.innerHTML = "";

      cart.forEach((item) => {
          subtotal += (item.p * (item.qty || 1));
          list.innerHTML += `
              <div class="item-row">
                  <div>
                      <div style="font-weight:bold; font-size:15px;">${item.n}</div>
                      ${item.selectedSub ? `<div style="font-size:12px; color:var(--primary);">${item.selectedSub}</div>` : ''}
                      <div style="color:var(--primary); font-size:13px;">₹${item.p}</div>
                  </div>
                  <div class="qty-ctrl">
                      <i class="fa fa-minus" onclick="updateQty('${item.n}', -1)" style="cursor:pointer;"></i>
                      <span>${item.qty || 1}</span>
                      <i class="fa fa-plus" onclick="updateQty('${item.n}', 1)" style="cursor:pointer;"></i>
                  </div>
              </div>`;
      });

      let final = (subtotal - appliedDiscount) + 10;
      document.getElementById('sTotal').innerText = "₹" + subtotal;
      document.getElementById('discountRowVal').innerText = "-₹" + appliedDiscount;
      document.getElementById('fTotal').innerText = "₹" + (final < 10 ? 10 : final);
  }

  function updateQty(name, change) {
      let item = cart.find(i => i.n === name);
      if (item) {
          item.qty = (item.qty || 1) + change;
          if (item.qty <= 0) {
              cart = cart.filter(i => i.n !== name);
          }
      }
      renderCart();
      document.getElementById('bCount').innerText = cart.reduce((acc, curr) => acc + (curr.qty || 1), 0);
      if(cart.length === 0) closeCart();
  }

  function setPayMode(mode) {
      selectedMode = mode;
      document.getElementById('payCash').style.borderColor = mode === 'Cash' ? 'var(--primary)' : '#ddd';
      document.getElementById('payCash').style.background = mode === 'Cash' ? 'var(--primary-light)' : 'var(--card-bg)';
      document.getElementById('payOnline').style.borderColor = mode === 'Online' ? 'var(--primary)' : '#ddd';
      document.getElementById('payOnline').style.background = mode === 'Online' ? 'var(--primary-light)' : 'var(--card-bg)';
  }

  function handleFinalOrder() {
      let address = document.getElementById('manualAddr').value.trim();
      let mobile = document.getElementById('altMobile').value.trim();
      let date = document.getElementById('cartDate').value;
      let time = document.getElementById('cartTime').value;
      let remark = document.getElementById('cartRemark').value.trim();
      let mapsLink = document.getElementById('googleMapsLink').value;

      if(!address) return showAlert("पता आवश्यक है", "कृपया अपनी डिलीवरी लोकेशन या पता दर्ज करें");
      if(!selectedMode) return showAlert("भुगतान मोड चुनें", "कृपया Cash या Online भुगतान का तरीका चुनें");

      let subtotal = cart.reduce((acc, curr) => acc + (curr.p * (curr.qty || 1)), 0);
      let finalAmt = (subtotal - appliedDiscount) + 10;
      if(finalAmt < 10) finalAmt = 10;

      let orderDetails = {
          id: 'SW' + Math.floor(100000 + Math.random() * 900000),
          items: cart,
          total: finalAmt,
          address: address,
          mobile: mobile || localStorage.getItem('sw_user') || '7869969190',
          date: date,
          time: time,
          remark: remark,
          mode: selectedMode,
          maps: mapsLink,
          status: 'Order Placed',
          timestamp: new Date().toLocaleString()
      };

      let history = JSON.parse(localStorage.getItem('sw_order_history')) || [];
      history.unshift(orderDetails);
      localStorage.setItem('sw_order_history', JSON.stringify(history));

      let orderMsg = `*🚀 New SewaAstra Booking!* %0A` +
                     `🆔 Order ID: ${orderDetails.id}%0A` +
                     `👤 User: ${orderDetails.mobile}%0A` +
                     `📦 Items: ${cart.map(i => i.n + ' (x' + (i.qty||1) + ')').join(', ')}%0A` +
                     `💰 Total Amount: ₹${finalAmt} (${selectedMode})%0A` +
                     `📍 Address: ${address}%0A` +
                     `🗺️ Map: ${mapsLink}%0A` +
                     `📅 Schedule: ${date} at ${time}%0A` +
                     `📝 Remark: ${remark || 'None'}`;

      closeCart();
      cart = [];
      document.getElementById('bCount').innerText = "0";

      showAlert("बुकिंग सफल! 🎉", `आपका ऑर्डर <b>${orderDetails.id}</b> सफलतापूर्वक दर्ज कर लिया गया है!<br><br>WhatsApp पर बुकिंग विवरण भेजा जा रहा है...`);
      
      setTimeout(() => {
          window.open(`https://wa.me/917869969190?text=${orderMsg}`, '_blank', 'noopener,noreferrer');
      }, 1500);
  }

  function showHistory() {
      let history = JSON.parse(localStorage.getItem('sw_order_history')) || [];
      if(history.length === 0) {
          return showAlert("ऑर्डर इतिहास", LANG_DATA[currentLang].noHistory);
      }

      let html = `<div style="text-align:left; max-height:70vh; overflow-y:auto;">`;
      history.forEach(o => {
          html += `
              <div style="background:var(--card-bg); border:1px solid #eee; padding:15px; border-radius:12px; margin-bottom:12px;">
                  <div style="display:flex; justify-content:space-between; font-weight:bold; font-size:14px; color:var(--primary);">
                      <span>${o.id}</span>
                      <span>₹${o.total} (${o.mode})</span>
                  </div>
                  <div style="font-size:12px; color:#666; margin:4px 0;">📅 ${o.date} | ⏰ ${o.time}</div>
                  <div style="font-size:12px; margin:4px 0;">📍 ${o.address}</div>
                  <div style="font-size:12px; color:#444; font-weight:600; margin-top:6px;">Items: ${o.items.map(i => i.n + ' (x' + (i.qty||1) + ')').join(', ')}</div>
                  <div style="display:flex; gap:8px; margin-top:10px;">
                      <button onclick="openLiveTracking('${o.id}')" style="flex:1; background:var(--primary); color:white; border:none; padding:8px; border-radius:8px; font-size:12px; font-weight:bold; cursor:pointer;"><i class="fa fa-map-marked-alt"></i> Live Tracking</button>
                  </div>
              </div>`;
      });
      html += `</div>`;
      showAlert("📦 आपका ऑर्डर इतिहास (Order History)", html);
  }

  function toggleProfile() {
      let overlay = document.getElementById('profileOverlay');
      overlay.style.display = (overlay.style.display === 'flex') ? 'none' : 'flex';
  }

  function closeProfile(e) {
      if(!e || e.target.id === 'profileOverlay') {
          document.getElementById('profileOverlay').style.display = 'none';
      }
  }

  function openSupportView() {
      document.getElementById('supportPage').style.display = 'block';
  }

  function closeSupportView() {
      document.getElementById('supportPage').style.display = 'none';
  }

  function selectSuppIssue(issue) {
      currentIssue = issue;
      document.getElementById('issueLabel').innerText = issue;
      document.getElementById('step1').style.display = 'none';
      document.getElementById('step2').style.display = 'block';
  }

  function resetSupportFlow() {
      document.getElementById('step1').style.display = 'block';
      document.getElementById('step2').style.display = 'none';
  }

  function talkToExpert(type) {
      let text = `Hello SewaAstra Support, I need help regarding: ${currentIssue}`;
      if (type === 'wa') {
          window.open(`https://wa.me/917869969190?text=${encodeURIComponent(text)}`, '_blank');
      } else {
          window.location.href = "tel:7869969190";
      }
  }

  function showToast(msg) {
      let t = document.getElementById('welcomeToast');
      t.innerText = msg;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3000);
  }

  function createCard(item, uniqueId) {
      let subOptionsHtml = "";
      if (item.subOptions && item.subOptions.length > 0) {
          subOptionsHtml = `<div class="service-sub-options" id="subOpt_${uniqueId}" style="display:flex;">
              <div style="font-size:11px; font-weight:bold; color:var(--primary); margin-bottom:4px;">विकल्प चुनें (Select Option):</div>`;
          item.subOptions.forEach((opt, idx) => {
              let checkedAttr = (idx === 0) ? 'checked' : '';
              subOptionsHtml += `<label><input type="radio" name="sub_${uniqueId}" value="${opt}" ${checkedAttr} onchange="updateCardPrice('${uniqueId}', ${item.p})"> ${opt}</label>`;
          });
          subOptionsHtml += `</div>`;
      }

      return `
          <div class="card">
              <div class="card-top">
                  <img loading="lazy" decoding="async" src="${item.i}" onclick="showAlert('${item.n}', 'बेहतरीन गुणवत्ता वाली होम सर्विस।')" />
                  <div class="card-info">
                      <h4>${item.n}</h4>
                      <div class="rating-row">
                          <i class="fa fa-star"></i>
                          <span class="rating-val">4.8</span>
                          <span class="review-count">(320+ reviews)</span>
                      </div>
                      <div class="price-row">
                          <b id="priceDisplay_${uniqueId}">₹${item.p}</b>
                          <button class="add-btn" id="btn_${uniqueId}" onclick="addToCart('${item.n}', ${item.p}, '${uniqueId}')">ADD</button>
                      </div>
                  </div>
              </div>
              ${subOptionsHtml}
          </div>`;
  }

  function updateCardPrice(uniqueId, basePrice) {
      let radios = document.getElementsByName(`sub_${uniqueId}`);
      let extra = 0;
      for (let r of radios) {
          if (r.checked) {
              let match = r.value.match(/\+₹(\d+)/);
              if (match) extra = parseInt(match[1]);
          }
      }
      document.getElementById(`priceDisplay_${uniqueId}`).innerText = "₹" + (basePrice + extra);
  }

  function addToCart(name, basePrice, uniqueId) {
      let radios = document.getElementsByName(`sub_${uniqueId}`);
      let selectedSub = "";
      let extra = 0;
      for (let r of radios) {
          if (r.checked) {
              selectedSub = r.value;
              let match = r.value.match(/\+₹(\d+)/);
              if (match) extra = parseInt(match[1]);
          }
      }

      let finalPrice = basePrice + extra;
      /* 🏷️ CATEGORY attach — jis category ka card, cart item me wahi category */
      let cat='', catName='';
      try{
        var ui=String(uniqueId||''), pos=ui.lastIndexOf('_'), ck=pos>0?ui.slice(0,pos):'';
        var co=categoriesData.find(function(c){ return c.key===ck; });
        if(co){ cat=co.key; catName=co.name; }
        else{
          var fk='';
          for(var k in mainData){ if(mainData[k] && mainData[k].some(function(s){ return s && s.n===name; })){ fk=k; break; } }
          if(fk){ var co2=categoriesData.find(function(c){ return c.key===fk; }); cat=fk; catName=co2?co2.name:fk; }
        }
        if(!cat){ cat='general'; catName='General'; }
      }catch(e){ cat='general'; catName='General'; }
      let existing = cart.find(i => i.n === name && i.selectedSub === selectedSub);
      if (existing) {
          existing.qty = (existing.qty || 1) + 1;
          if(!existing.cat){ existing.cat=cat; existing.catName=catName; }
      } else {
          cart.push({ n: name, p: finalPrice, selectedSub: selectedSub, qty: 1, cat: cat, catName: catName });
      }

      let btn = document.getElementById(`btn_${uniqueId}`);
      btn.classList.add('filled');
      btn.innerText = "ADDED ✓";
      setTimeout(() => { btn.classList.remove('filled'); btn.innerText = "ADD"; }, 1200);

      let totalCount = cart.reduce((acc, curr) => acc + (curr.qty || 1), 0);
      document.getElementById('bCount').innerText = totalCount;
      showToast(`${name} कार्ट में जोड़ दिया गया! 🛒`);
  }

  function load(catKey) {
      let display = document.getElementById('display');
      display.innerHTML = "";
      let catObj = categoriesData.find(c => c.key === catKey);
      document.getElementById('catTitle').innerText = catObj ? catObj.name + " Services" : "Recommended Services";

      if(mainData[catKey]) {
          mainData[catKey].forEach((s, idx) => {
              display.innerHTML += createCard(s, catKey + '_' + idx);
          });
      }
  }

  // Initial App Startup
  window.onload = function() {
      renderCategoriesGrid();
      renderBanners();
      load(categoriesData[0].key);

      let isDark = localStorage.getItem('sw_dark') === 'true';
      if (isDark) {
          document.body.classList.add('dark-mode');
          document.getElementById('darkBtn').checked = true;
      }

      let savedPhoto = localStorage.getItem('sw_user_photo');
      if (savedPhoto) {
          document.getElementById('headerPic').src = savedPhoto;
          document.getElementById('sheetPic').src = savedPhoto;
      }

      try{ firebase.auth().setPersistence(firebase.auth.Auth.Persistence.LOCAL).catch(function(){}); }catch(e){} let logged = localStorage.getItem('sw_logged'); try{ var __u=String(localStorage.getItem('sw_user')||''); /* 🔒 B-3: सिर्फ नंबर होने से logged-in नहीं माना जाएगा */ }catch(e){}
      let user = localStorage.getItem('sw_user');
      if (logged && user) {
          document.getElementById('authOverlay').style.display = 'none';
          document.getElementById('profilePhoneDisplay').innerText = user.includes('@') ? user : "+91 " + user;
          checkAdminAccess(user);
          fetchCityNameByGPS();
      }
  };

/* ═══ ब्लॉक 6 ═══ जान-बूझकर नहीं लपेटा: इसके top-level
   let/const दूसरे ब्लॉक इस्तेमाल करते हैं, और try{} के अंदर
   वे इसी ब्लॉक तक सिमट जाते. */
/* ═══════════════════════════════════════════════════════════════════
   SEWAASTRA PRO — CLOUD UPGRADE LAYER (v2.0)
   Yeh layer original code ke UPAR chalti hai aur sab kuch REAL banati hai:
   ✅ Orders ab Firestore me save (har device pe dikhte hain)
   ✅ Admin ke Services/Categories/Banners/Coupons ab CLOUD me (sab users ko dikhte hain)
   ✅ Real-time Order History + live status updates + notifications
   ✅ Admin ORDERS tab — status change karo, customer ko turant dikhega
   ✅ REAL chat (customer ↔ admin) per order
   ✅ Rating & review system
   ✅ Order cancel + UPI online payment link
   ═══════════════════════════════════════════════════════════════════ */

/* ─────────────── HELPERS ─────────────── */
const FS = firebase.firestore();
try{ SWID.install(FS); }catch(e){ console.warn('SWID', e); }
const STATUS_LIST = ['Order Placed', 'Accepted', 'On the Way', 'Working', 'Completed', 'Cancelled'];
const STATUS_HI = {
  'Order Placed': '📦 ऑर्डर प्राप्त', 'Accepted': '✅ स्वीकृत', 'On the Way': '🛵 रास्ते में',
  'Working': '🔧 काम चालू', 'Completed': '🎉 पूर्ण', 'Cancelled': '❌ रद्द'
};
const STATUS_CLR = {
  'Order Placed': '#b26a00', 'Accepted': '#14538c', 'On the Way': '#7b2ff2',
  'Working': '#0d6efd', 'Completed': '#28a745', 'Cancelled': '#e53935'
};
function proEsc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function getUID() { try { return firebase.auth().currentUser ? firebase.auth().currentUser.uid : null; } catch (e) { return null; } }
function getIdent() { return localStorage.getItem('sw_user') || ''; }
function isAdminUser(){ /* 🔒 C-1: अब सिर्फ Firebase custom claim — localStorage नहीं */ try{ return !!(window.SWSec && window.SWSec.isAdmin); }catch(e){ return false; } }
let CLOUD_CONFIG = {};   // {upiId, ...}
let myOrdersCache = {};  // id -> status (notification diff ke liye)
let unsubMyOrders = null, unsubAllOrders = null, unsubChat = null;
let activeChatOrderId = null;

/* ═══════════════ 1. CLOUD CONFIG SYNC (admin data sab jagah real) ═══════════════ */
function pushConfigToCloud() {
  const payload = {
    categoriesData: JSON.stringify(categoriesData),
    mainData: JSON.stringify(mainData),
    bannersData: JSON.stringify(bannersData),
    couponsData: JSON.stringify(couponsData),
    upiId: CLOUD_CONFIG.upiId || '',
    updatedAt: Date.now()
  };
  FS.collection('app_config').doc('main').set(payload, { merge: true })
    .then(() => showToast('☁️ Cloud me save ho gaya — sab users ko dikhega!'))
    .catch(e => showToast('Cloud sync error: ' + e.message));
}

function applyCloudConfig(d) {
  try {
    if (d.categoriesData) { categoriesData = JSON.parse(d.categoriesData); localStorage.setItem('sw_custom_categories', d.categoriesData); }
    if (d.mainData) { mainData = JSON.parse(d.mainData); localStorage.setItem('sw_custom_services', d.mainData); }
    if (d.bannersData) { bannersData = JSON.parse(d.bannersData); localStorage.setItem('sw_custom_banners', d.bannersData); }
    if (d.couponsData) { couponsData = JSON.parse(d.couponsData); localStorage.setItem('sw_custom_coupons', d.couponsData); }
    CLOUD_CONFIG.upiId = d.upiId || '';
    try { renderCategoriesGrid(); } catch (e) {}
    try { renderBanners(); } catch (e) {}
    try { renderMoreCategoriesGrid(); } catch (e) {}
  } catch (e) { console.warn('config apply:', e); }
}

FS.collection('app_config').doc('main').onSnapshot(snap => {
  if (snap.exists) applyCloudConfig(snap.data());
  else if (isAdminUser()) pushConfigToCloud();   // pehli baar admin device se seed
}, e => console.warn('config listen:', e));

/* Admin save/delete functions ko wrap karo — original chalega, phir cloud push */
['saveAdminCategory', 'deleteAdminCategory', 'saveAdminServiceChanges',
 'saveAdminBannerChanges', 'saveAdminCouponChanges'].forEach(fn => {
  const orig = window[fn];
  if (typeof orig === 'function') {
    window[fn] = function () { orig.apply(this, arguments); pushConfigToCloud(); };
  }
});

/* ═══════════════ 2. REAL ORDERS (Firestore me save) ═══════════════ */
window.handleFinalOrder = function () {
  let address = document.getElementById('manualAddr').value.trim();
  let mobile = document.getElementById('altMobile').value.trim();
  let date = document.getElementById('cartDate').value;
  let time = document.getElementById('cartTime').value;
  let remark = document.getElementById('cartRemark').value.trim();
  let mapsLink = document.getElementById('googleMapsLink').value;

  if (!address) return showAlert('पता आवश्यक है', 'कृपया अपनी डिलीवरी लोकेशन या पता दर्ज करें');
  if (!selectedMode) return showAlert('भुगतान मोड चुनें', 'कृपया Cash या Online भुगतान का तरीका चुनें');
  if (!cart.length) return showAlert('कार्ट खाली है', 'पहले कोई सेवा जोड़ें');

  let subtotal = cart.reduce((acc, c) => acc + (c.p * (c.qty || 1)), 0);
  let finalAmt = (subtotal - appliedDiscount) + 10;
  if (finalAmt < 10) finalAmt = 10;

  const oid = 'SW' + Math.floor(100000 + Math.random() * 900000);
  const userMobile = mobile || getIdent() || '';
  const order = {
    id: oid,
    uid: getUID(),
    mobile: userMobile,
    items: cart.map(i => ({ n: i.n, p: i.p, qty: i.qty || 1, cat: i.cat || '', catName: i.catName || '' })),
    subtotal, discount: appliedDiscount, total: finalAmt,
    address, date, time, remark, mode: selectedMode, maps: mapsLink || '',
      cats: (function(){ var s={},out=[]; (cart||[]).forEach(function(i){ var k=i.cat||'general', nn=i.catName||'General'; if(!s[k]){s[k]=1; out.push({key:k,name:nn});} }); return out; })(),
    status: 'Order Placed', rated: false,
    loc: (typeof userCoords !== 'undefined' ? {lat: userCoords.lat, lon: userCoords.lon} : null),
    createdAt: Date.now(),
    timestamp: new Date().toLocaleString('hi-IN')
  };

  showLoader('ऑर्डर सेव हो रहा है...');
  FS.collection('orders').doc(oid).set(order).then(() => {
    hideLoader();
    // offline cache bhi rakho
    let hist = JSON.parse(localStorage.getItem('sw_order_history')) || [];
    hist.unshift(order);
    localStorage.setItem('sw_order_history', JSON.stringify(hist.slice(0, 50)));

    const waMsg = `*🚀 New SewaAstra Booking!*%0A🆔 Order ID: ${oid}%0A👤 User: ${userMobile}%0A📦 Items: ${cart.map(i => i.n + ' (x' + (i.qty || 1) + ')').join(', ')}%0A💰 Total: ₹${finalAmt} (${selectedMode})%0A📍 Address: ${address}%0A🗺️ Map: ${mapsLink}%0A📅 ${date} at ${time}%0A📝 ${remark || 'None'}`;

    closeCart();
    cart = [];
    try { renderCart(); } catch (e) {}
    document.getElementById('bCount').innerText = '0';
    appliedDiscount = 0;

    let extra = '';
    if (selectedMode === 'Online' && CLOUD_CONFIG.upiId) {
      const upi = `upi://pay?pa=${encodeURIComponent(CLOUD_CONFIG.upiId)}&pn=SewaAstra&am=${finalAmt}&cu=INR&tn=${oid}`;
      extra = `<br><a href="${upi}" style="display:inline-block;margin-top:10px;background:#15a04a;color:#fff;padding:10px 18px;border-radius:10px;text-decoration:none;font-weight:bold;">💳 UPI से ₹${finalAmt} Pay करें</a>`;
    }
    showAlert('बुकिंग सफल! 🎉', `आपका ऑर्डर <b>${oid}</b> ☁️ cloud में सेव हो गया है!<br>स्टेटस अपडेट आपको यहीं मिलेंगे (📋 History में देखें)।${extra}<br><br>WhatsApp पर विवरण भेजा जा रहा है...`);
    setTimeout(() => { window.open(`https://wa.me/917869969190?text=${waMsg}`, '_blank', 'noopener,noreferrer'); }, 1800);
    startMyOrdersListener();
  }).catch(e => {
    hideLoader();
    showAlert('त्रुटि', 'ऑर्डर सेव नहीं हो सका: ' + e.message);
  });
};

/* ═══════════════ 3. REAL ORDER HISTORY + NOTIFICATIONS ═══════════════ */
function myOrdersQuery() {
  const uid = getUID();
  if (uid) return FS.collection('orders').where('uid', '==', uid);
  const ident = getIdent();
  return SWID.orderQuery(FS,'customer') || FS.collection('orders').where('mobile', '==', ident);
}

function swCxPop(t,m){ try{ var ov=document.getElementById('swCxEvOv'); if(!ov){ ov=document.createElement('div'); ov.id='swCxEvOv'; document.body.appendChild(ov); } ov.style.cssText='position:fixed;inset:0;z-index:2147483635;display:flex;align-items:center;justify-content:center;padding:22px;background:rgba(5,8,18,.82);font-family:system-ui,Arial,sans-serif;box-sizing:border-box;'; ov.style.display='flex'; ov.innerHTML='<div style="background:#fff;border-radius:24px;padding:24px;max-width:320px;width:100%;text-align:center;color:#222;"><div style="font-weight:900;font-size:16px;">'+t+'</div><div style="font-size:13px;color:#555;margin:8px 0 14px;line-height:1.6;">'+SWSec.esc(m)+'</div><button id="swCxEvX" style="width:100%;border:none;border-radius:13px;padding:13px;font-weight:900;background:#111;color:#fff;cursor:pointer;">OK</button></div>'; document.getElementById('swCxEvX').onclick=function(){ ov.style.display='none'; }; }catch(e){} } function swCxEvt(o){ try{ if(o.status==='Cancelled'){ swCxPop('Order Cancel ho gaya','Kaaran: '+((o.cancelReason||o.cancelledBy)||'nahi likha')); return; } if(o.status==='Completed'){ swCxPop('Kaam Complete!','Partner ne kaam pura kar diya. Kripya rating dein.'); setTimeout(function(){ try{ if(typeof openRateModal==='function'){ openRateModal(o.id); } else if(window.openRateModal){ window.openRateModal(o.id); } }catch(e){} },3000); return; } }catch(e){} } function startMyOrdersListener() {
  if (isAdminUser()) return;             // admin apna tab use karega
  if (unsubMyOrders) unsubMyOrders();
  if (!getUID() && !getIdent()) return;
  unsubMyOrders = myOrdersQuery().onSnapshot(snap => {
    snap.docChanges().forEach(ch => {
      const o = ch.doc.data();
      if (ch.type === 'modified' && myOrdersCache[o.id] && myOrdersCache[o.id] !== o.status) {
        showToast(`🔔 ऑर्डर ${o.id}: ${STATUS_HI[o.status] || o.status}`);
      }
      try{ if(ch.type==='modified'&&myOrdersCache[o.id]&&myOrdersCache[o.id]!==o.status){ try{ swCxEvt(o); }catch(e){} } }catch(e){} myOrdersCache[o.id] = o.status;
    });
  }, e => console.warn('orders listen:', e));
}

window.showHistory = function () {
  showLoader('इतिहास लोड हो रहा है...');
  myOrdersQuery().get().then(snap => {
    hideLoader();
    let orders = snap.docs.map(d => d.data());
    if (!orders.length) return showAlert('ऑर्डर इतिहास', 'अभी तक कोई ऑर्डर नहीं है।');
    orders.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    let html = `<div style="text-align:left; max-height:65vh; overflow-y:auto;">`;
    orders.forEach(o => {
      const clr = STATUS_CLR[o.status] || '#666';
      const canCancel = ['Order Placed', 'Accepted'].includes(o.status);
      const canRate = o.status === 'Completed' && !o.rated;
      html += `
      <div style="background:var(--card-bg); border:1px solid var(--border-color); padding:14px; border-radius:12px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; font-weight:bold; font-size:14px;">
          <span style="color:var(--primary);">${o.id}</span>
          <span style="background:${clr}22;color:${clr};padding:3px 10px;border-radius:12px;font-size:11px;">${STATUS_HI[o.status] || o.status}</span>
        </div>
        <div style="font-size:12px; color:#888; margin:4px 0;">📅 ${proEsc(o.date)} | ⏰ ${proEsc(o.time)} | ₹${o.total} (${o.mode})</div>
        <div style="font-size:12px; margin:4px 0;">📍 ${proEsc(o.address)}</div>
        <div style="font-size:12px; font-weight:600; margin-top:4px;">🛠️ ${(o.items || []).map(i => proEsc(i.n) + ' (x' + (i.qty || 1) + ')').join(', ')}</div>
        ${o.rated ? `<div style="font-size:12px;color:#f5a623;font-weight:bold;margin-top:4px;">⭐ आपने रेटिंग दे दी है</div>` : ''}
        <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap;">
          <button onclick="openLiveTracking('${o.id}')" style="flex:1;min-width:90px;background:var(--primary);color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:bold;cursor:pointer;">🗺️ Tracking</button>
          <button onclick="openOrderChat('${o.id}')" style="flex:1;min-width:90px;background:#0d6efd;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:bold;cursor:pointer;">💬 Chat</button>
          ${canRate ? `<button onclick="openRateModal('${o.id}')" style="flex:1;min-width:90px;background:#f5a623;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:bold;cursor:pointer;">⭐ Rate</button>` : ''}
          ${canCancel ? `<button onclick="cancelMyOrder('${o.id}')" style="flex:1;min-width:90px;background:#e53935;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:bold;cursor:pointer;">❌ Cancel</button>` : ''}
        </div>
      </div>`;
    });
    html += `</div>`;
    showAlert('📋 मेरे ऑर्डर (Live)', html);
  }).catch(e => { hideLoader(); showAlert('त्रुटि', e.message); });
};

window.cancelMyOrder = function (oid) { try{ window.__cxReason=''; var __r=prompt('Cancel kaaran likhein (partner ko dikhega):',''); if(__r===null) return; window.__cxReason=String(__r||'').slice(0,200)||'Customer ne cancel kiya'; }catch(e){ window.__cxReason='Customer ne cancel kiya'; }
  swUi.confirm({icon:'🚫',title:'ऑर्डर रद्द करें?',msg:`ऑर्डर ${oid} रद्द करना है?`,ok:'हाँ, रद्द करें',cancel:'रुकें',danger:true,onOk:function(){
    FS.collection('orders').doc(oid).update({ status: 'Cancelled', cancelReason: (window.__cxReason||'Customer ne cancel kiya'), cancelledBy: 'customer', cancelledAt: Date.now() })
      .then(() => { showToast('❌ ऑर्डर रद्द हो गया'); closeCustomAlert(); setTimeout(showHistory, 400); })
      .catch(e => showAlert('त्रुटि', e.message));
  }});
};

/* ═══════════════ 4. REAL CHAT (per order, customer ↔ admin) ═══════════════ */
window.openOrderChat = function (oid) {
  activeChatOrderId = oid;
  closeCustomAlert();
  document.getElementById('chatCallModal').style.display = 'flex';
  const box = document.getElementById('chatMsgContainer');
  box.innerHTML = `<div style="text-align:center;font-size:11px;color:#999;margin-bottom:8px;">📦 Order ${oid} — Live Chat</div>`;
  if (unsubChat) unsubChat();
  unsubChat = FS.collection('orders').doc(oid).collection('chats')
    .onSnapshot(snap => {
      const msgs = snap.docs.map(d => d.data()).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      const myRole = isAdminUser() ? 'admin' : 'user';
      box.innerHTML = `<div style="text-align:center;font-size:11px;color:#999;margin-bottom:8px;">📦 Order ${oid} — Live Chat</div>` +
        msgs.map(m => `<div class="chat-bubble ${m.sender === myRole ? 'user' : 'partner'}">${proEsc(m.text)}</div>`).join('');
      box.scrollTop = box.scrollHeight;
    }, e => { box.innerHTML += `<div style="color:red;font-size:12px;">Chat error: ${proEsc(e.message)}</div>`; });
};

/* purana generic chat bhi order chat ban jaye */
window.openInAppChat = function () {
  // latest active order dhundo
  myOrdersQuery().get().then(snap => {
    let orders = snap.docs.map(d => d.data()).filter(o => !['Completed', 'Cancelled'].includes(o.status));
    orders.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    if (orders.length) openOrderChat(orders[0].id);
    else showAlert('चैट', 'कोई active ऑर्डर नहीं है। पहले कोई सेवा बुक करें, फिर उस ऑर्डर पर चैट करें।');
  }).catch(() => { document.getElementById('chatCallModal').style.display = 'flex'; });
};

window.sendChatMessage = function () {
  const input = document.getElementById('chatInputMsg');
  const text = input.value.trim();
  if (!text) return;
  if (!activeChatOrderId) return showToast('पहले कोई ऑर्डर चुनें');
  input.value = '';
  FS.collection('orders').doc(activeChatOrderId).collection('chats').add({
    text, sender: isAdminUser() ? 'admin' : 'user',
    by: getIdent() || getUID() || 'anon', ts: Date.now()
  }).catch(e => showToast('भेज नहीं सका: ' + e.message));
};

/* ═══════════════ 5. RATING SYSTEM ═══════════════ */
let currentRating = 5;
window.openRateModal = function (oid) {
  closeCustomAlert();
  currentRating = 5;
  const html = `
    <div style="text-align:center;">
      <div id="proStars" style="font-size:34px; cursor:pointer; margin:10px 0;">
        ${[1, 2, 3, 4, 5].map(i => `<span data-s="${i}" onclick="setProRating(${i})" style="color:#f5a623;">★</span>`).join('')}
      </div>
      <textarea id="proRateCmt" placeholder="अपना अनुभव लिखें..." style="width:100%;border:1px solid var(--border-color);border-radius:10px;padding:10px;font-size:13px;min-height:60px;background:var(--card-bg);color:var(--text);"></textarea>
      <button onclick="submitProRating('${oid}')" style="width:100%;margin-top:10px;background:var(--primary);color:#fff;border:none;padding:12px;border-radius:10px;font-weight:bold;cursor:pointer;">SUBMIT REVIEW</button>
    </div>`;
  showAlert('⭐ सेवा को रेट करें', html);
};
window.setProRating = function (n) {
  currentRating = n;
  document.querySelectorAll('#proStars span').forEach(s => {
    s.style.color = (+s.dataset.s <= n) ? '#f5a623' : '#ccc';
  });
};
window.submitProRating = function (oid) {
  const cmt = (document.getElementById('proRateCmt')?.value || '').trim();
  FS.collection('reviews').add({
    orderId: oid, rating: currentRating, comment: cmt,
    // 🔒 यहाँ कभी फोन नंबर नहीं — reviews सबके लिए खुली हैं.
    //    पहले getIdent() (यानी फोन) जाता था — कोई भी सारे ग्राहक नंबर उठा लेता.
    by: getUID() || 'anon', ts: Date.now()
  }).then(() => FS.collection('orders').doc(oid).update({ rated: true, rating: currentRating }))
    .then(() => { closeCustomAlert(); showToast('⭐ धन्यवाद! रिव्यू सेव हो गया'); })
    .catch(e => showAlert('त्रुटि', e.message));
};

/* ═══════════════ 6. ADMIN ORDERS TAB (real-time management) ═══════════════ */
function injectAdminOrdersTab() {
  const tabRow = document.getElementById('admTabServBtn')?.parentElement;
  const modalBody = document.getElementById('adminSecServices')?.parentElement;
  if (!tabRow || !modalBody || document.getElementById('admTabOrdersBtn')) return;

  const btn = document.createElement('button');
  btn.id = 'admTabOrdersBtn';
  btn.innerHTML = '📦 Orders';
  btn.setAttribute('style', 'flex:1; padding:8px; border:none; border-radius:8px; font-weight:bold; background:transparent; color:#555; font-size:11px; cursor:pointer;');
  btn.onclick = () => switchAdminTab('orders');
  tabRow.insertBefore(btn, tabRow.firstChild);

  const sec = document.createElement('div');
  sec.id = 'adminSecOrders';
  sec.style.display = 'none';
  sec.innerHTML = `
    <div id="admOrderStats" style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px;"></div>
    <div style="display:flex;gap:6px;margin-bottom:10px;">
      <input id="admUpiId" placeholder="अपनी UPI ID (online payment के लिए)" style="flex:1;border:1px solid #ddd;border-radius:8px;padding:8px;font-size:12px;">
      <button onclick="saveAdminUpi()" style="background:var(--primary);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-size:12px;font-weight:bold;cursor:pointer;">Save</button>
    </div>
    <div id="admOrdersList" style="max-height:55vh;overflow-y:auto;">Loading...</div>`;
  modalBody.appendChild(sec);
}

const _origSwitchAdminTab = window.switchAdminTab;
window.switchAdminTab = function (tab) {
  injectAdminOrdersTab();
  const sec = document.getElementById('adminSecOrders');
  const btn = document.getElementById('admTabOrdersBtn');
  if (tab === 'orders') {
    _origSwitchAdminTab('services');            // baaki sab hide + unke buttons reset
    document.getElementById('adminSecServices').style.display = 'none';
    sec.style.display = 'block';
    btn.style.background = 'var(--primary)'; btn.style.color = 'white';
    document.getElementById('admTabServBtn').style.background = 'transparent';
    document.getElementById('admTabServBtn').style.color = '#555';
    startAllOrdersListener();
    document.getElementById('admUpiId').value = CLOUD_CONFIG.upiId || '';
  } else {
    if (sec) sec.style.display = 'none';
    if (btn) { btn.style.background = 'transparent'; btn.style.color = '#555'; }
    _origSwitchAdminTab(tab);
  }
};

window.saveAdminUpi = function () {
  CLOUD_CONFIG.upiId = document.getElementById('admUpiId').value.trim();
  pushConfigToCloud();
};

function startAllOrdersListener() {
  /* SCALE: पूरी orders collection नहीं — LIVE active + हाल के 150 (bounded) */
  if (window.__scAllO) return; window.__scAllO = 1;
  var seen = {};
  function pushOrders(snap) {
    snap.docs.forEach(function(d){ var o=d.data(); if(o&&(o.id||d.id)) seen[o.id||d.id]=o; });
    var list = [];
    for (var k in seen) list.push(seen[k]);
    list.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
    try { renderAdminOrders(list.slice(0,100)); } catch(err) {}
  }
  var errH = function(e){ var el=document.getElementById('admOrdersList'); if(el) el.innerHTML='Error: '+proEsc(e.message); };
  try {
    FS.collection('orders').where('status','in',['Order Placed','Accepted','On the Way','Working']).onSnapshot(pushOrders, errH);
    FS.collection('orders').orderBy('createdAt','desc').limit(150).onSnapshot(pushOrders, errH);
  } catch(e) { errH(e); }
}

function renderAdminOrders(orders) {
  const list = document.getElementById('admOrdersList');
  const statsEl = document.getElementById('admOrderStats');
  if (!list) return;
  const todayStr = new Date().toDateString();
  const todayCnt = orders.filter(o => new Date(o.createdAt || 0).toDateString() === todayStr).length;
  const pending = orders.filter(o => !['Completed', 'Cancelled'].includes(o.status)).length;
  const revenue = orders.filter(o => o.status === 'Completed').reduce((s, o) => s + (o.total || 0), 0);
  if (statsEl) statsEl.innerHTML = ['<b>' + todayCnt + '</b><span>आज के ऑर्डर</span>', '<b>' + pending + '</b><span>Active</span>', '<b>₹' + revenue.toLocaleString('en-IN') + '</b><span>Revenue</span>']
    .map(x => `<div style="background:var(--primary-light);border-radius:10px;padding:10px;text-align:center;font-size:11px;display:flex;flex-direction:column;gap:2px;color:#333;">${x}</div>`).join('');

  if (!orders.length) { list.innerHTML = '<p style="text-align:center;color:#999;">कोई ऑर्डर नहीं</p>'; return; }
  list.innerHTML = orders.map(o => {
    const clr = STATUS_CLR[o.status] || '#666';
    return `
    <div style="border:1px solid var(--border-color);border-radius:12px;padding:12px;margin-bottom:10px;background:var(--card-bg);">
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:13px;font-weight:bold;">
        <span style="color:var(--primary);">${o.id}</span>
        <span style="color:${clr};font-size:11px;">${STATUS_HI[o.status] || o.status}</span>
      </div>
      <div style="font-size:11.5px;color:#888;margin:3px 0;">📞 ${proEsc(o.mobile)} | 📅 ${proEsc(o.date)} ${proEsc(o.time)} | ₹${o.total} (${o.mode})</div>
      <div style="font-size:11.5px;margin:3px 0;">📍 ${proEsc(o.address)}</div>
      <div style="font-size:11.5px;font-weight:600;">🛠️ ${(o.items || []).map(i => proEsc(i.n) + ' x' + (i.qty || 1)).join(', ')}</div>
      ${o.remark ? `<div style="font-size:11px;color:#a06;margin-top:2px;">📝 ${proEsc(o.remark)}</div>` : ''}
      ${o.rating ? `<div style="font-size:11px;color:#f5a623;font-weight:bold;">⭐ Customer rating: ${o.rating}/5</div>` : ''}
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center;">
        <select onchange="adminSetStatus('${o.id}', this.value)" style="flex:1;min-width:120px;border:1px solid #ddd;border-radius:8px;padding:6px;font-size:11px;">
          ${STATUS_LIST.map(s => `<option value="${s}" ${s === o.status ? 'selected' : ''}>${STATUS_HI[s]}</option>`).join('')}
        </select>
        <button onclick="openOrderChat('${o.id}')" style="background:#0d6efd;color:#fff;border:none;border-radius:8px;padding:7px 10px;font-size:11px;font-weight:bold;cursor:pointer;">💬</button>
        <a href="tel:${o.mobile}" style="background:#28a745;color:#fff;border-radius:8px;padding:7px 10px;font-size:11px;text-decoration:none;font-weight:bold;">📞</a>
        ${o.maps ? `<a href="${proEsc(o.maps)}" target="_blank" style="background:#7b2ff2;color:#fff;border-radius:8px;padding:7px 10px;font-size:11px;text-decoration:none;font-weight:bold;" rel="noopener noreferrer">🗺️</a>` : ''}
        <a href="https://wa.me/91${proEsc(o.mobile)}" target="_blank" style="background:#25D366;color:#fff;border-radius:8px;padding:7px 10px;font-size:11px;text-decoration:none;font-weight:bold;" rel="noopener noreferrer">WA</a>
      </div>
    </div>`;
  }).join('');
}

window.adminSetStatus = function (oid, status) {
  FS.collection('orders').doc(oid).update({ status })
    .then(() => showToast(`${oid} → ${STATUS_HI[status]}`))
    .catch(e => showAlert('त्रुटि', e.message));
};

/* ═══════════════ 7. STARTUP ═══════════════ */
try {
  firebase.auth().onAuthStateChanged(u => { if (u) startMyOrdersListener(); });
} catch (e) {}
setTimeout(() => {
  if (localStorage.getItem('sw_logged')) startMyOrdersListener();
  if (isAdminUser()) injectAdminOrdersTab();
}, 2500);
console.log('%c SewaAstra PRO Cloud Layer v2.0 active ☁️✅ ', 'background:#ff6b00;color:#fff;font-weight:bold;padding:4px;');

/* ═══ ब्लॉक 7 ═══ */
try {
/* Premium touch: time-based greeting chip under header */
(function(){
  try{
    var h = new Date().getHours();
    var g = h < 12 ? 'सुप्रभात 🌅' : h < 17 ? 'नमस्ते ☀️' : 'शुभ संध्या 🌆';
    var header = document.querySelector('.app-header .search-container');
    if(header){
      var chip = document.createElement('div');
      chip.style.cssText = 'margin-top:10px;display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.3);color:#fff;font-size:11.5px;font-weight:700;padding:5px 12px;border-radius:16px;backdrop-filter:blur(6px);';
      chip.innerHTML = g + ' — आज कौन सा काम करवाना है?';
      header.parentNode.insertBefore(chip, header.nextSibling);
    }
  }catch(e){}
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 7 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([7, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 8 ═══ */
try {
/* ═══════════════════════════════════════════════════════════════
   SEWAASTRA PRO-MAX LAYER v2.2
   ✅ Banner auto-scroll carousel
   ✅ Service card → expandable multi-service options
   ✅ REAL live tracking (partner GPS → customer map, Firestore realtime)
   ✅ Admin: 📡 Live Location Share + premium orders list
   ═══════════════════════════════════════════════════════════════ */

/* ─────── 1. BANNER AUTO-SCROLL ─────── */
(function () {
  let bannerTimer = null, pauseUntil = 0;
  function startBannerAuto() {
    const el = document.getElementById('bannerCarouselArea');
    if (!el) return;
    if (bannerTimer) clearInterval(bannerTimer);
    ['touchstart', 'mousedown'].forEach(ev =>
      el.addEventListener(ev, () => { pauseUntil = Date.now() + 6000; }, { passive: true }));
    bannerTimer = setInterval(() => {
      if (Date.now() < pauseUntil) return;
      if (!el.children.length) return;
      const cardW = el.children[0].offsetWidth + 12;
      const maxScroll = el.scrollWidth - el.clientWidth - 10;
      if (el.scrollLeft >= maxScroll) el.scrollTo({ left: 0, behavior: 'smooth' });
      else el.scrollBy({ left: cardW, behavior: 'smooth' });
    }, 3200);
  }
  setTimeout(startBannerAuto, 1500);
  setInterval(() => {   // agar banners baad me render hue
    const el = document.getElementById('bannerCarouselArea');
    if (el && el.children.length && !bannerTimer) startBannerAuto();
  }, 4000);
})();

/* ─────── 2. MULTI-SERVICE OPTIONS (expandable on click) ─────── */
(function () {
  function enhanceCards() {
    document.querySelectorAll('#display .card').forEach(card => {
      if (card.dataset.proEnh) return;
      const sub = card.querySelector('.service-sub-options');
      if (!sub) { card.dataset.proEnh = '1'; return; }
      card.dataset.proEnh = '1';
      sub.style.display = 'none';
      const optCount = sub.querySelectorAll('label').length;
      const chip = document.createElement('button');
      chip.innerHTML = `🧩 ${optCount} विकल्प उपलब्ध — देखें <i class="fa fa-chevron-down" style="font-size:10px;"></i>`;
      chip.style.cssText = 'width:100%;margin-top:2px;background:#fff5ed;color:#ff6b00;border:1.5px dashed #ffb066;border-radius:12px;padding:9px;font-size:12px;font-weight:800;cursor:pointer;transition:all .2s;';
      chip.onclick = function (e) {
        e.stopPropagation();
        const open = sub.style.display !== 'none';
        sub.style.display = open ? 'none' : 'flex';
        chip.innerHTML = open
          ? `🧩 ${optCount} विकल्प उपलब्ध — देखें <i class="fa fa-chevron-down" style="font-size:10px;"></i>`
          : `🧩 विकल्प चुनें <i class="fa fa-chevron-up" style="font-size:10px;"></i>`;
        chip.style.background = open ? '#fff5ed' : '#ff6b00';
        chip.style.color = open ? '#ff6b00' : '#fff';
      };
      sub.parentNode.insertBefore(chip, sub);
    });
  }
  const disp = document.getElementById('display');
  if (disp) new MutationObserver(enhanceCards).observe(disp, { childList: true, subtree: false });
  setTimeout(enhanceCards, 1200);
})();

/* ─────── 3. REAL LIVE TRACKING (Firestore + Leaflet) ─────── */
let proTrackMap = null, proCustMarker = null, proPartnerMarker = null,
    proTrackLine = null, unsubTrack = null;

const TRACK_STEPS = [
  { s: 'Order Placed', ic: '📦', lb: 'ऑर्डर' },
  { s: 'Accepted', ic: '✅', lb: 'स्वीकृत' },
  { s: 'On the Way', ic: '🛵', lb: 'रास्ते में' },
  { s: 'Working', ic: '🔧', lb: 'काम चालू' },
  { s: 'Completed', ic: '🎉', lb: 'पूर्ण' }
];

window.openLiveTracking = function (oid) {
  closeCustomAlert();
  const modal = document.getElementById('liveTrackingModal');
  modal.style.display = 'flex';

  // map init (fresh)
  setTimeout(() => {
    if (proTrackMap) { try { proTrackMap.remove(); } catch (e) {} proTrackMap = null; }
    proCustMarker = proPartnerMarker = proTrackLine = null;
    proTrackMap = L.map('trackingMapContainer').setView([userCoords.lat, userCoords.lon], 14);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19 }).addTo(proTrackMap);
    subscribeTrack(oid);
  }, 300);
};

function subscribeTrack(oid) {
  if (unsubTrack) unsubTrack();
  const infoEl = document.querySelector('#liveTrackingModal > div:last-of-type');
  unsubTrack = FS.collection('orders').doc(oid).onSnapshot(snap => {
    if (!snap.exists) return;
    const o = snap.data();
    const custLoc = o.loc && o.loc.lat ? [o.loc.lat, o.loc.lon] : [userCoords.lat, userCoords.lon];
    const pLoc = o.partnerLoc && o.partnerLoc.lat ? [o.partnerLoc.lat, o.partnerLoc.lon] : null;

    if (proTrackMap) {
      if (!proCustMarker) {
        proCustMarker = L.marker(custLoc).addTo(proTrackMap).bindPopup('🏠 आपकी लोकेशन');
      } else proCustMarker.setLatLng(custLoc);

      if (pLoc) {
        const bikeIcon = L.divIcon({ html: '<div style="font-size:26px;filter:drop-shadow(0 3px 5px rgba(0,0,0,.4));">🛵</div>', className: '', iconSize: [30, 30] });
        if (!proPartnerMarker) proPartnerMarker = L.marker(pLoc, { icon: bikeIcon }).addTo(proTrackMap).bindPopup('👨‍🔧 SewaAstra Partner');
        else proPartnerMarker.setLatLng(pLoc);
        if (proTrackLine) proTrackMap.removeLayer(proTrackLine);
        proTrackLine = L.polyline([pLoc, custLoc], { color: '#ff6b00', weight: 4, dashArray: '8 8', opacity: .8 }).addTo(proTrackMap);
        try { proTrackMap.fitBounds([pLoc, custLoc], { padding: [45, 45] }); } catch (e) {}
      }
    }

    // premium status timeline + info
    const curIdx = TRACK_STEPS.findIndex(t => t.s === o.status);
    const isCancelled = o.status === 'Cancelled';
    const freshLoc = pLoc && o.partnerLoc.ts && (Date.now() - o.partnerLoc.ts < 120000);
    /* 📏 दूरी + ⏱️ ETA + 🕐 last update (feature: partner map time के साथ) */
    let dTxt='—', etaTxt='—', lastTxt='—', navLn='';
    if (pLoc && Array.isArray(pLoc) && pLoc.length>=2) {
      try {
        const R=6371, dLa=(pLoc[0]-custLoc[0])*Math.PI/180, dLo=(pLoc[1]-custLoc[1])*Math.PI/180;
        const a2=Math.sin(dLa/2)*Math.sin(dLa/2)+Math.cos(custLoc[0]*Math.PI/180)*Math.cos(pLoc[0]*Math.PI/180)*Math.sin(dLo/2)*Math.sin(dLo/2);
        const km=2*R*Math.asin(Math.sqrt(a2));
        dTxt = km<1 ? Math.round(km*1000)+' m' : km.toFixed(1)+' km';
        const mins = Math.max(1, Math.ceil(km/18*60));      // ~18 km/h avg city speed
        etaTxt = mins+' min';
        const age = Math.max(0, Math.round((Date.now()-(o.partnerLoc.ts||0))/1000));
        lastTxt = (age<60? age+' sec' : Math.round(age/60)+' min')+' पहले';
        navLn = 'https://www.google.com/maps/dir/'+custLoc[0]+','+custLoc[1]+'/'+pLoc[0]+','+pLoc[1];
      } catch(e) {}
    }
    if (infoEl) {
      infoEl.innerHTML = `
        <div style="font-weight:800;font-size:14px;display:flex;justify-content:space-between;align-items:center;">
          <span>📦 ${oid}</span>
          <span style="color:${isCancelled ? '#e53935' : '#15a04a'};font-size:12px;">${STATUS_HI[o.status] || o.status}</span>
        </div>
        ${isCancelled ? `<p style="color:#e53935;font-size:13px;margin:8px 0;">यह ऑर्डर रद्द हो चुका है।</p>` : `
        <div class="pro-timeline">
          ${TRACK_STEPS.map((t, i) => `
            <div class="pro-step ${i < curIdx ? 'done' : i === curIdx ? 'now' : ''}">
              <div class="dot">${t.ic}</div><span>${t.lb}</span>
            </div>`).join('')}
        </div>
        <div style="font-size:12px;color:${freshLoc ? '#15a04a' : '#888'};font-weight:700;margin:6px 0;">
          ${freshLoc ? '🟢 पार्टनर की LIVE लोकेशन दिख रही है' : pLoc ? '🟡 पार्टनर की आखिरी लोकेशन' : '⏳ पार्टनर की लोकेशन का इंतज़ार — काम शुरू होते ही यहाँ दिखेगी'}
        </div>
        ${pLoc ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin:0 0 6px;">
          <span style="background:rgba(21,160,74,.12);color:#0f7a37;border-radius:12px;padding:5px 10px;font-size:10.5px;font-weight:900;">📏 दूरी: ${dTxt}</span>
          <span style="background:rgba(13,110,253,.12);color:#0d6efd;border-radius:12px;padding:5px 10px;font-size:10.5px;font-weight:900;">⏱️ ETA: ~${etaTxt}</span>
          <span style="background:rgba(176,120,0,.14);color:#8a5a00;border-radius:12px;padding:5px 10px;font-size:10.5px;font-weight:900;">🕐 last ${lastTxt}</span>
        </div>
        <a href="${navLn}" target="_blank" style="display:block;text-align:center;background:#0d47a1;color:#fff;text-decoration:none;border-radius:11px;padding:9px;font-size:11.5px;font-weight:900;margin-bottom:6px;" rel="noopener noreferrer">🧭 Partner तक Navigation (Google Maps)</a>` : ''}`}
        <div style="display:flex;gap:10px;margin-top:8px;">
          <button onclick="openMaskCall('${oid}')" style="flex:1;background:#15a04a;color:#fff;border:none;padding:11px;border-radius:12px;font-weight:800;cursor:pointer;"><i class="fa fa-phone-alt"></i> 🔒 Masked Call</button>
          <button onclick="closeLiveTracking();openOrderChat('${oid}')" style="flex:1;background:#ff6b00;color:#fff;border:none;padding:11px;border-radius:12px;font-weight:800;cursor:pointer;"><i class="fa fa-comment-dots"></i> Live Chat</button>
        </div>`;
    }
  }, e => console.warn('track:', e));
}

const _origCloseLT = window.closeLiveTracking;
window.closeLiveTracking = function () {
  if (unsubTrack) { unsubTrack(); unsubTrack = null; }
  if (proTrackMap) { try { proTrackMap.remove(); } catch (e) {} proTrackMap = null; }
  proCustMarker = proPartnerMarker = proTrackLine = null;
  try { _origCloseLT(); } catch (e) { document.getElementById('liveTrackingModal').style.display = 'none'; }
};

/* ─────── 4. ADMIN: LIVE LOCATION SHARE + premium orders ─────── */
let proWatchers = {};   // oid -> geolocation watchId

window.adminShareLoc = function (oid) {
  if (proWatchers[oid] !== undefined) {          // stop sharing
    navigator.geolocation.clearWatch(proWatchers[oid]);
    delete proWatchers[oid];
    FS.collection('orders').doc(oid).update({ sharing: false });
    showToast('📡 Location sharing बंद');
    return;
  }
  if (!navigator.geolocation) return showToast('GPS उपलब्ध नहीं है');
  let lastPush = 0;
  const wid = navigator.geolocation.watchPosition(pos => {
    if (Date.now() - lastPush < 4000) return;
    lastPush = Date.now();
    FS.collection('orders').doc(oid).update({
      partnerLoc: { lat: pos.coords.latitude, lon: pos.coords.longitude, ts: Date.now() },
      sharing: true
    }).catch(() => {});
  }, err => showToast('GPS error: ' + err.message), { enableHighAccuracy: true, maximumAge: 3000 });
  proWatchers[oid] = wid;
  showToast('📡 LIVE location share शुरू — customer को दिखेगी');
  FS.collection('orders').doc(oid).update({ sharing: true });
};

/* premium admin orders renderer (overrides v2.0 wala) */
window.renderAdminOrders = function (orders) {
  const list = document.getElementById('admOrdersList');
  const statsEl = document.getElementById('admOrderStats');
  if (!list) return;
  const todayStr = new Date().toDateString();
  const todayCnt = orders.filter(o => new Date(o.createdAt || 0).toDateString() === todayStr).length;
  const pending = orders.filter(o => !['Completed', 'Cancelled'].includes(o.status)).length;
  const revenue = orders.filter(o => o.status === 'Completed').reduce((s, o) => s + (o.total || 0), 0);
  if (statsEl) statsEl.innerHTML = ['<b>' + todayCnt + '</b><span>आज के ऑर्डर</span>', '<b>' + pending + '</b><span>Active</span>', '<b>₹' + revenue.toLocaleString('en-IN') + '</b><span>Revenue</span>']
    .map(x => `<div style="background:var(--primary-light);border-radius:12px;padding:12px;text-align:center;font-size:11px;display:flex;flex-direction:column;gap:2px;color:#333;">${x}</div>`).join('');

  if (!orders.length) { list.innerHTML = '<p style="text-align:center;color:#999;">कोई ऑर्डर नहीं</p>'; return; }
  list.innerHTML = orders.map(o => {
    const clr = STATUS_CLR[o.status] || '#666';
    const sharing = proWatchers[o.id] !== undefined;
    return `
    <div style="border:1px solid var(--border-color);border-radius:16px;padding:13px;margin-bottom:11px;background:var(--card-bg);box-shadow:0 4px 12px rgba(13,30,60,.06);">
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:13px;font-weight:800;">
        <span style="color:var(--primary);">${o.id}</span>
        <span style="background:${clr}22;color:${clr};padding:3px 10px;border-radius:12px;font-size:10.5px;">${STATUS_HI[o.status] || o.status}</span>
      </div>
      <div style="font-size:11.5px;color:#888;margin:4px 0;">📞 ${proEsc(o.mobile)} | 📅 ${proEsc(o.date)} ${proEsc(o.time)} | <b style="color:#15a04a;">₹${o.total}</b> (${o.mode})</div>
      <div style="font-size:11.5px;margin:3px 0;">📍 ${proEsc(o.address)}</div>
      <div style="font-size:11.5px;font-weight:700;">🛠️ ${(o.items || []).map(i => proEsc(i.n) + ' x' + (i.qty || 1)).join(', ')}</div>
      ${o.remark ? `<div style="font-size:11px;color:#a06;margin-top:2px;">📝 ${proEsc(o.remark)}</div>` : ''}
      ${o.rating ? `<div style="font-size:11px;color:#f5a623;font-weight:800;">⭐ Customer rating: ${o.rating}/5</div>` : ''}
      ${o.sharing ? `<div style="font-size:10.5px;color:#15a04a;font-weight:800;">🟢 Live location share ON</div>` : ''}
      <div style="display:flex;gap:6px;margin-top:9px;flex-wrap:wrap;align-items:center;">
        <select onchange="adminSetStatus('${o.id}', this.value)" style="flex:1;min-width:118px;border:1.5px solid #eadfd4;border-radius:10px;padding:7px;font-size:11px;font-weight:700;">
          ${STATUS_LIST.map(s => `<option value="${s}" ${s === o.status ? 'selected' : ''}>${STATUS_HI[s]}</option>`).join('')}
        </select>
        <button onclick="adminShareLoc('${o.id}')" title="Live location share" style="background:${sharing ? '#e53935' : '#7b2ff2'};color:#fff;border:none;border-radius:10px;padding:8px 10px;font-size:11px;font-weight:800;cursor:pointer;">📡${sharing ? ' STOP' : ''}</button>
        <button onclick="openOrderChat('${o.id}')" style="background:#0d6efd;color:#fff;border:none;border-radius:10px;padding:8px 10px;font-size:11px;font-weight:800;cursor:pointer;">💬</button>
        <a href="tel:${o.mobile}" style="background:#28a745;color:#fff;border-radius:10px;padding:8px 10px;font-size:11px;text-decoration:none;font-weight:800;">📞</a>
        ${o.maps && o.maps !== 'Not Provided' ? `<a href="${proEsc(o.maps)}" target="_blank" style="background:#ff6b00;color:#fff;border-radius:10px;padding:8px 10px;font-size:11px;text-decoration:none;font-weight:800;" rel="noopener noreferrer">🗺️</a>` : ''}
        <a href="https://wa.me/91${proEsc(o.mobile)}" target="_blank" style="background:#25D366;color:#fff;border-radius:10px;padding:8px 10px;font-size:11px;text-decoration:none;font-weight:800;" rel="noopener noreferrer">WA</a>
      </div>
    </div>`;
  }).join('');
};

console.log('%c SewaAstra PRO-MAX v2.2 ✅ auto-banner | multi-options | REAL tracking ', 'background:#15a04a;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 8 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([8, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 9 ═══ */
try {
/* SEWAASTRA v23 — History Delete + Ultra Premium Cart */

/* 1. CART EXTRAS (wrap renderCart) */
(function(){
  const _rc = window.renderCart;
  window.renderCart = function(){
    _rc();
    try{
      const list = document.getElementById('cartItemsList');
      if(!cart.length){
        list.innerHTML = `<div class="pro-cart-empty">
          <span class="ic">🛒</span>
          <div style="font-weight:900;font-size:15px;margin:8px 0 4px;">आपका कार्ट खाली है</div>
          <div style="font-size:12px;color:#888;margin-bottom:12px;">कोई भी सर्विस चुनें — expert घर आएगा!</div>
          <button onclick="closeCart()" style="background:linear-gradient(90deg,#ff6b00,#ff8c2e);color:#fff;border:none;border-radius:12px;padding:11px 26px;font-weight:800;font-size:13px;cursor:pointer;box-shadow:0 6px 16px rgba(255,107,0,.35);">🛠️ Services देखें</button>
        </div>`;
      } else {
        const totalItems = cart.reduce((s,i)=>s+(i.qty||1),0);
        list.insertAdjacentHTML('afterbegin',
          `<div class="pro-cart-count">🛠️ ${cart.length} सर्विस • ${totalItems} आइटम</div>`);
      }
      const fT = document.getElementById('fTotal');
      const billCard = fT ? fT.closest('.cart-card') : null;
      const oldChip = document.getElementById('proSaveChip');
      if(oldChip) oldChip.remove();
      if(billCard && appliedDiscount > 0){
        billCard.insertAdjacentHTML('beforeend',
          `<div id="proSaveChip" class="pro-save-chip">🎉 बधाई हो! आप इस ऑर्डर पर <b>₹${appliedDiscount}</b> बचा रहे हैं</div>`);
      }
      if(fT){ fT.classList.remove('pop'); void fT.offsetWidth; fT.classList.add('pop');
        setTimeout(()=>fT.classList.remove('pop'), 400); }
    }catch(e){}
  };
})();

/* 2. HISTORY DELETE */
window.deleteMyOrder = function(oid){
  swUi.confirm({icon:'🗑️',title:'ऑर्डर delete करें?',msg:`ऑर्डर ${oid} को history से हमेशा के लिए delete करना है?`,ok:'हाँ, delete करें',cancel:'रुकें',danger:true,onOk:function(){
    FS.collection('orders').doc(oid).delete()
      .then(()=>{ showToast('🗑️ ऑर्डर delete हो गया'); closeCustomAlert(); setTimeout(showHistory, 350); })
      .catch(e=>showAlert('त्रुटि', e.message));
  }});
};

window.clearMyHistory = function(){
  swUi.confirm({icon:'🧹',title:'History साफ करें?',msg:'सभी पूर्ण/रद्द ऑर्डर history से delete हो जाएंगे। पक्का?',ok:'हाँ, साफ करें',cancel:'रुकें',danger:true,onOk:function(){
    showLoader('History साफ़ हो रही है...');
    myOrdersQuery().get().then(snap=>{
      const batch = FS.batch();
      let n = 0;
      snap.docs.forEach(d=>{
        const s = d.data().status;
        if(s === 'Completed' || s === 'Cancelled'){ batch.delete(d.ref); n++; }
      });
      return batch.commit().then(()=>n);
    }).then(n=>{
      hideLoader(); closeCustomAlert();
      showToast(n ? `🗑️ ${n} ऑर्डर delete हो गए` : 'कोई पूर्ण/रद्द ऑर्डर नहीं मिला');
      setTimeout(showHistory, 400);
    }).catch(e=>{ hideLoader(); showAlert('त्रुटि', e.message); });
  }});
};

/* 3. HISTORY UI (overrides v2.0 — delete buttons ke saath) */
window.showHistory = function(){
  showLoader('इतिहास लोड हो रहा है...');
  myOrdersQuery().get().then(snap=>{
    hideLoader();
    let orders = snap.docs.map(d=>d.data());
    if(!orders.length) return showAlert('ऑर्डर इतिहास', 'अभी तक कोई ऑर्डर नहीं है।');
    orders.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
    const doneCnt = orders.filter(o=>['Completed','Cancelled'].includes(o.status)).length;
    let html = `<div style="text-align:left; max-height:65vh; overflow-y:auto;">`;
    if(doneCnt) html += `<button onclick="clearMyHistory()" style="width:100%;background:#fdecea;color:#e53935;border:1.5px dashed #f5c6c3;border-radius:12px;padding:10px;font-weight:800;font-size:12px;cursor:pointer;margin-bottom:12px;">🗑️ पूरी History साफ़ करें (${doneCnt} पुराने ऑर्डर)</button>`;
    orders.forEach(o=>{
      const clr = STATUS_CLR[o.status] || '#666';
      const canCancel = ['Order Placed','Accepted'].includes(o.status);
      const canRate = o.status === 'Completed' && !o.rated;
      const canDel = ['Completed','Cancelled'].includes(o.status);
      html += `
      <div style="background:var(--card-bg); border:1px solid var(--border-color); padding:14px; border-radius:14px; margin-bottom:12px; box-shadow:0 4px 12px rgba(13,30,60,.06);">
        <div style="display:flex; justify-content:space-between; align-items:center; font-weight:800; font-size:14px;">
          <span style="color:var(--primary);">${o.id}</span>
          <span style="background:${clr}22;color:${clr};padding:3px 10px;border-radius:12px;font-size:11px;">${STATUS_HI[o.status] || o.status}</span>
        </div>
        <div style="font-size:12px; color:#888; margin:4px 0;">📅 ${proEsc(o.date)} | ⏰ ${proEsc(o.time)} | <b style="color:#15a04a;">₹${o.total}</b> (${o.mode})</div>
        <div style="font-size:12px; margin:4px 0;">📍 ${proEsc(o.address)}</div>
        <div style="font-size:12px; font-weight:700; margin-top:4px;">🛠️ ${(o.items||[]).map(i=>proEsc(i.n)+' (x'+(i.qty||1)+')').join(', ')}</div>
        ${o.rated ? `<div style="font-size:12px;color:#f5a623;font-weight:800;margin-top:4px;">⭐ आपने रेटिंग दे दी है</div>` : ''}
        <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap;">
          <button onclick="openLiveTracking('${o.id}')" style="flex:1;min-width:84px;background:var(--primary);color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">🗺️ Tracking</button>
          <button onclick="openOrderChat('${o.id}')" style="flex:1;min-width:70px;background:#0d6efd;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">💬 Chat</button>
          ${canRate ? `<button onclick="openRateModal('${o.id}')" style="flex:1;min-width:70px;background:#f5a623;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">⭐ Rate</button>` : ''}
          ${canCancel ? `<button onclick="cancelMyOrder('${o.id}')" style="flex:1;min-width:70px;background:#e53935;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">❌ Cancel</button>` : ''}
          ${canDel ? `<button class="pro-hist-del" onclick="deleteMyOrder('${o.id}')" title="Delete">🗑️</button>` : ''}
        </div>
      </div>`;
    });
    html += `</div>`;
    showAlert('📋 मेरे ऑर्डर (Live)', html);
  }).catch(e=>{ hideLoader(); showAlert('त्रुटि', e.message); });
};

console.log('%c SewaAstra v2.3 FINAL ✅ history-delete | ultra cart ', 'background:#0d6efd;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 9 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([9, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 10 ═══ */
try {
/* ═══════════ SEWAASTRA v24 LAYER ═══════════
   1. Customer profile → Firestore users/{mobile ya gmail}
   2. Admin fullscreen + 👥 Users tab
   3. Service click → photo option picker sheet
*/

/* ---------- 1. CUSTOMER DATA (users collection) ---------- */
function proSaveProfile(){
  try{
    const u = firebase.auth().currentUser;
    const stored = (localStorage.getItem('sw_user')||'').trim();
    const phone = /^\d{10}$/.test(stored) ? stored : '';
    const email = (u && u.email) || (stored.indexOf('@')>-1 ? stored : '');
    const key = phone || email;
    if(!key) return;
    const data = {
      phone: phone || null,
      email: email || null,
      name: (u && u.displayName) || null,
      photo: localStorage.getItem('sw_user_photo') || (u && u.photoURL) || null,
      uid: u ? u.uid : null,
      provider: (u && u.providerData && u.providerData[0]) ? u.providerData[0].providerId : 'phone',
      city: (document.getElementById('cityName')||{innerText:''}).innerText || null,
      lastLogin: Date.now(),
      lastLoginAt: new Date().toLocaleString('en-IN'),
      logins: firebase.firestore.FieldValue.increment(1)
    };
    Object.keys(data).forEach(k=>{ if(data[k]===null) delete data[k]; });
    const ref = FS.collection('users').doc(String(key));
    ref.get().then(d=>{
      if(!d.exists) data.createdAt = new Date().toLocaleString('en-IN');
      return ref.set(data, {merge:true});
    }).then(()=>console.log('👤 profile saved →', key))
      .catch(e=>console.log('profile err', e.message));
  }catch(e){ console.log('profile', e); }
}
firebase.auth().onAuthStateChanged(u=>{ if(u) setTimeout(proSaveProfile, 1500); });
(function(){
  const _g = window.submitGoogleLinkedPhone;
  window.submitGoogleLinkedPhone = function(){ _g(); setTimeout(proSaveProfile, 800); };
})();

/* ---------- 2. ADMIN: 👥 USERS TAB + LIST ---------- */
window.openCustomersList = function(){
  showLoader('Customers लोड हो रहे हैं...');
  FS.collection('users').orderBy('lastLogin','desc').limit(150).get().then(snap=>{
    hideLoader();
    if(snap.empty) return showAlert('👥 Customers', 'अभी तक कोई customer login नहीं हुआ है।');
    let users = snap.docs.map(d=>({id:d.id, ...d.data()}));
    users.sort((a,b)=>(b.lastLogin||0)-(a.lastLogin||0));
    let html = `<div style="text-align:left;max-height:65vh;overflow-y:auto;">
      <div style="font-size:12px;font-weight:800;color:#888;margin-bottom:10px;">हाल के ${users.length} customers (सब लाखों हों तो Cloud console से पूरा export)</div>`;
    users.forEach(c=>{
      const ph = c.phone ? String(c.phone) : '';
      html += `<div class="pro-cust-card">
        <div class="av">${c.photo ? `<img src="${proEsc(c.photo)}" onerror="this.parentElement.innerHTML='👤'">` : '👤'}</div>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:900;font-size:13.5px;">${proEsc(c.name || ph || c.email || c.id)}</div>
          ${ph ? `<div style="font-size:11.5px;color:#666;">📱 +91 ${proEsc(ph)}</div>` : ''}
          ${c.email ? `<div style="font-size:11px;color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">✉️ ${proEsc(c.email)}</div>` : ''}
          <div style="font-size:10px;color:#999;margin-top:2px;">🕐 ${proEsc(c.lastLoginAt||'')} • ${c.logins||1} logins • ${proEsc(c.provider||'')}</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:5px;">
          ${ph ? `<a href="tel:+91${ph}" style="background:#15a04a;color:#fff;padding:6px 9px;border-radius:8px;font-size:11px;text-decoration:none;">📞</a>
          <a href="https://wa.me/91${ph}" target="_blank" style="background:#25d366;color:#fff;padding:6px 9px;border-radius:8px;font-size:11px;text-decoration:none;" rel="noopener noreferrer">💬</a>` : ''}
        </div>
      </div>`;
    });
    html += `</div>`;
    showAlert('👥 Customers (Firebase)', html);
  }).catch(e=>{ hideLoader(); showAlert('त्रुटि', e.message); });
};
(function(){
  const tabRow = document.querySelector('#adminModal .box > div:nth-child(2)');
  if(tabRow && !document.getElementById('admTabCustBtn')){
    const b = document.createElement('button');
    b.id = 'admTabCustBtn';
    b.innerHTML = '👥 Users';
    b.setAttribute('style','flex:1;padding:8px;border:none;border-radius:8px;font-weight:bold;background:transparent;color:var(--text);font-size:11px;cursor:pointer;');
    b.onclick = openCustomersList;
    tabRow.appendChild(b);
  }
})();

/* ---------- 3. SERVICE CLICK → PHOTO OPTION PICKER ---------- */
document.body.insertAdjacentHTML('beforeend', `
<div id="svcOptModal" onclick="if(event.target===this)closeSvcOpt()">
  <div class="svc-sheet">
    <div class="svc-hero">
      <img id="svcHeroImg" src="" alt="">
      <div class="svc-close" onclick="closeSvcOpt()"><i class="fa fa-times"></i></div>
      <div class="tt"><h3 id="svcHeroName"></h3>
        <div class="sub">⭐ 4.8 (320+ reviews) • ✅ Verified Expert</div></div>
    </div>
    <div id="svcOptBody"></div>
    <div class="svc-foot">
      <div><div class="lbl">कुल कीमत</div><div class="tot" id="svcFootPrice">₹0</div></div>
      <button onclick="svcAddNow()">🛒 कार्ट में जोड़ें</button>
    </div>
  </div>
</div>`);

window.__svcSel = null;

window.openSvcOptions = function(el){
  const card = el.closest('.card');
  if(!card) return;
  const h4 = card.querySelector('h4');
  const img = card.querySelector('img');
  const btn = card.querySelector('.add-btn');
  if(!h4 || !btn) return;
  const uid = btn.id.replace('btn_','');
  const name = h4.innerText.trim();
  const src = img ? img.src : '';
  const radios = card.querySelectorAll(`input[name="sub_${uid}"]`);
  let base = 0, opts = [], idx = 0;
  if(radios.length){
    const oc = radios[0].getAttribute('onchange') || '';
    const m = oc.match(/,\s*(\d+)\s*\)/);
    base = m ? parseInt(m[1]) : 0;
    radios.forEach((r,i)=>{
      const em = r.value.match(/\+₹(\d+)/);
      opts.push({ v: r.value, extra: em ? parseInt(em[1]) : 0 });
      if(r.checked) idx = i;
    });
  } else {
    const pd = card.querySelector('#priceDisplay_'+uid);
    base = pd ? parseInt(pd.innerText.replace(/[^\d]/g,'')||'0') : 0;
  }
  window.__svcSel = { uid, name, src, base, opts, idx };

  document.getElementById('svcHeroImg').src = src;
  document.getElementById('svcHeroName').innerText = name;
  const body = document.getElementById('svcOptBody');
  if(opts.length){
    let h = `<div class="svc-opt-head">🧩 अपना विकल्प चुनें (${opts.length} options)</div>`;
    opts.forEach((o,i)=>{
      h += `<div class="svc-opt-card ${i===idx?'sel':''}" data-i="${i}" onclick="svcPick(${i})">
        <img src="${src}" alt="">
        <div><div class="nm">${proEsc(o.v.replace(/\s*\(\+₹\d+\)\s*/,''))}</div>
        <div class="pr">₹${base + o.extra}${o.extra?` <span style="color:#999;font-weight:700;font-size:10px;">(+₹${o.extra})</span>`:''}</div></div>
        <div class="tick"><i class="fa fa-check"></i></div>
      </div>`;
    });
    body.innerHTML = h;
  } else {
    body.innerHTML = `<div class="svc-opt-head">✨ सर्विस विवरण</div>
      <div style="margin:0 16px 14px;font-size:13px;color:#777;line-height:1.6;">
        बेहतरीन गुणवत्ता वाली होम सर्विस — प्रशिक्षित और verified expert आपके घर आएगा। 
        सभी tools और genuine parts के साथ। ✅ Service warranty उपलब्ध।
      </div>`;
  }
  svcUpdatePrice();
  document.getElementById('svcOptModal').classList.add('open');
};

window.svcPick = function(i){
  const s = window.__svcSel; if(!s) return;
  s.idx = i;
  document.querySelectorAll('#svcOptBody .svc-opt-card').forEach(c=>{
    c.classList.toggle('sel', +c.dataset.i === i);
  });
  svcUpdatePrice();
};

function svcUpdatePrice(){
  const s = window.__svcSel; if(!s) return;
  const extra = s.opts.length ? s.opts[s.idx].extra : 0;
  const el = document.getElementById('svcFootPrice');
  el.innerText = '₹' + (s.base + extra);
  el.classList.remove('pop'); void el.offsetWidth; el.classList.add('pop');
}

window.svcAddNow = function(){
  const s = window.__svcSel; if(!s) return;
  if(s.opts.length){
    const radios = document.getElementsByName('sub_'+s.uid);
    for(let r of radios) r.checked = (r.value === s.opts[s.idx].v);
    if(typeof updateCardPrice === 'function') updateCardPrice(s.uid, s.base);
  }
  addToCart(s.name, s.base, s.uid);
  closeSvcOpt();
};

window.closeSvcOpt = function(){
  document.getElementById('svcOptModal').classList.remove('open');
};

/* photo/naam par click → picker (purana alert hatao) */
(function(){
  const disp = document.getElementById('display');
  if(!disp) return;
  function enh(){
    disp.querySelectorAll('.card img, .card h4').forEach(el=>{
      if(el.dataset.v24) return;
      el.dataset.v24 = '1';
      el.removeAttribute('onclick');
      el.style.cursor = 'pointer';
      el.addEventListener('click', ()=>openSvcOptions(el));
    });
  }
  new MutationObserver(enh).observe(disp, {childList:true, subtree:true});
  enh();
})();

console.log('%c SewaAstra v2.4 ✅ fullscreen-admin | users-db | photo-options ', 'background:#7b2ff7;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 10 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([10, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 11 ═══ */
try {
/* ═══════════ SEWAASTRA v25 — SMART APP INSTALL POPUP ═══════════
   - Har NAYE customer ko login ke turant baad popup
   - "बाद में" = sirf 24 ghante snooze (hamesha band nahi)
   - App installed ho to kabhi nahi dikhega
   - Home par floating "📲 App" pill bhi
*/

window.proDeferredPrompt = null;
window.addEventListener('beforeinstallprompt', function(e){
  e.preventDefault();
  window.proDeferredPrompt = e;
  proMaybeShowPill();
});
window.addEventListener('appinstalled', function(){
  localStorage.setItem('sw_app_installed', 'true');
  var p = document.getElementById('proInstallPill');
  if(p) p.style.display = 'none';
  showToast('🎉 SewaAstra ऐप install हो गया!');
});

function proIsStandalone(){
  return window.matchMedia('(display-mode: standalone)').matches
      || window.navigator.standalone === true
      || localStorage.getItem('sw_app_installed') === 'true';
}
function proInstallSnoozed(){
  var t = parseInt(localStorage.getItem('sw_install_snooze') || '0');
  return Date.now() < t;
}
function proShowInstallModal(){
  if(proIsStandalone()) return;
  var m = document.getElementById('installAppModal');
  if(!m) return;
  /* trust badges ek baar add karo */
  if(!m.querySelector('.pro-inst-badge')){
    var btn = m.querySelector('button[onclick^="triggerAppInstall"]');
    if(btn) btn.insertAdjacentHTML('beforebegin',
      '<div class="pro-inst-badge"><span>🔒 100% Safe</span><span>⚡ Instant Install</span><span>📦 सिर्फ 1 MB</span></div>');
  }
  m.style.display = 'flex';
}

/* login ke baad — har naye customer ko (installed nahi + snooze khatam) */
window.checkAndShowInstallModalAfterLogin = function(){
  if(proIsStandalone() || proInstallSnoozed()) return;
  setTimeout(proShowInstallModal, 1200);
};

/* Install button — captured prompt use karo */
window.triggerAppInstall = function(){
  document.getElementById('installAppModal').style.display = 'none';
  if(window.proDeferredPrompt){
    window.proDeferredPrompt.prompt();
    window.proDeferredPrompt.userChoice.then(function(ch){
      if(ch.outcome === 'accepted'){
        localStorage.setItem('sw_app_installed', 'true');
        showToast('SewaAstra ऐप install हो रहा है! 🎉');
      } else {
        localStorage.setItem('sw_install_snooze', String(Date.now() + 24*60*60*1000));
      }
      window.proDeferredPrompt = null;
    });
  } else {
    showAlert('📲 ऐप इनस्टॉल करें',
      'अपने ब्राउज़र मेनू <b>(⋮)</b> में जाकर <b>"Add to Home Screen"</b> या <b>"Install App"</b> पर टैप करें — SewaAstra आपकी होम स्क्रीन पर ऐप की तरह आ जाएगा! ⚡');
  }
};

/* "बाद में" = 24 ghante snooze, hamesha ke liye band NahI */
window.closeInstallModal = function(){
  document.getElementById('installAppModal').style.display = 'none';
  localStorage.setItem('sw_install_snooze', String(Date.now() + 24*60*60*1000));
  proMaybeShowPill();
};

/* HOME SCREEN par bhi: logged-in user + app installed nahi → popup */
window.addEventListener('load', function(){
  setTimeout(function(){
    var authVisible = false;
    var a = document.getElementById('authOverlay');
    if(a && getComputedStyle(a).display !== 'none') authVisible = true;
    if(!authVisible && localStorage.getItem('sw_logged') === 'true'
       && !proIsStandalone() && !proInstallSnoozed()){
      proShowInstallModal();
    }
    proMaybeShowPill();
  }, 2500);
});

/* floating pill — popup band hone ke baad bhi ek chhota reminder */
function proMaybeShowPill(){
  if(proIsStandalone()) return;
  if(localStorage.getItem('sw_logged') !== 'true') return;
  var p = document.getElementById('proInstallPill');
  if(!p){
    document.body.insertAdjacentHTML('beforeend',
      '<div id="proInstallPill" onclick="proShowInstallModal()"><span class="dot"></span>📲 App डाउनलोड करें</div>');
    p = document.getElementById('proInstallPill');
  }
  p.style.display = 'flex';
}

console.log('%c SewaAstra v2.5 ✅ smart install popup ', 'background:#15a04a;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 11 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([11, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 12 ═══ */
try {
/* ═══════════ SEWAASTRA v26 ═══════════
   1. Admin panel scroll fix (CSS)
   2. Kaam Complete → customer ko AUTO rating popup
   3. Rating partner ke Firebase data me save (partners/{phone})
   4. Admin orders me bhi Delete button
*/

var PRO_PARTNER_PHONE = '7869969190';
var proRatePrompted = {};

/* ---------- AUTO RATING POPUP (jab partner kaam complete kare) ---------- */
function proStartRatingWatcher(){
  try{
    if (typeof isAdminUser === 'function' && isAdminUser()) return;
    if (!getUID() && !getIdent()) return;
    if (window.__proRateUnsub) window.__proRateUnsub();
    window.__proRateUnsub = myOrdersQuery().onSnapshot(function(snap){
      snap.docChanges().forEach(function(ch){
        var o = ch.doc.data();
        if (o.status === 'Completed' && !o.rated && !proRatePrompted[o.id]){
          proRatePrompted[o.id] = true;
          if (ch.type === 'modified'){
            /* partner ne ABHI complete kiya → turant popup */
            showToast('🎉 आपका काम पूरा हो गया!');
            setTimeout(function(){ openRateModal(o.id); }, 900);
          } else if (ch.type === 'added'){
            /* app khola aur pehle se koi un-rated completed order pada hai */
            setTimeout(function(){ openRateModal(o.id); }, 2500);
          }
        }
      });
    }, function(e){ console.warn('rate watch:', e.message); });
  }catch(e){ console.log(e); }
}
firebase.auth().onAuthStateChanged(function(u){ if(u) setTimeout(proStartRatingWatcher, 1800); });
window.addEventListener('load', function(){
  if (localStorage.getItem('sw_logged') === 'true') setTimeout(proStartRatingWatcher, 3000);
});

/* ---------- PREMIUM RATING MODAL ---------- */
var PRO_RATE_EMOJI = {1:'😞 बहुत खराब', 2:'😕 खराब', 3:'😐 ठीक-ठाक', 4:'😊 अच्छा', 5:'🤩 शानदार!'};

window.openRateModal = function(oid){
  closeCustomAlert();
  currentRating = 5;
  var html = '<div style="text-align:center;">' +
    '<div class="pro-rate-hero">🧑‍🔧</div>' +
    '<div style="font-weight:900;font-size:14px;">हमारे expert का काम कैसा रहा?</div>' +
    '<div style="font-size:11px;color:#999;margin-bottom:4px;">Order: ' + proEsc(oid) + '</div>' +
    '<div id="proStars" style="font-size:38px;cursor:pointer;margin:8px 0 2px;">' +
      [1,2,3,4,5].map(function(i){ return '<span data-s="' + i + '" onclick="setProRating(' + i + ')" style="color:#f5a623;">★</span>'; }).join('') +
    '</div>' +
    '<div id="proRateEmoji">🤩 शानदार!</div>' +
    '<div style="margin-bottom:8px;">' +
      ['⚡ समय पर सेवा','✨ बढ़िया काम','🙏 विनम्र व्यवहार','🧰 सही tools','💰 सही कीमत'].map(function(c){
        return '<span class="pro-rate-chip" onclick="proRateChip(this)">' + c + '</span>';
      }).join('') +
    '</div>' +
    '<textarea id="proRateCmt" placeholder="अपना अनुभव लिखें..." style="width:100%;border:1px solid var(--border-color);border-radius:12px;padding:10px;font-size:13px;min-height:56px;background:var(--card-bg);color:var(--text);"></textarea>' +
    '<button onclick="submitProRating(\'' + oid + '\')" style="width:100%;margin-top:10px;background:linear-gradient(90deg,#ff6b00,#ff8c2e);color:#fff;border:none;padding:14px;border-radius:14px;font-weight:900;font-size:14px;cursor:pointer;box-shadow:0 8px 20px rgba(255,107,0,.35);">⭐ रिव्यू सबमिट करें</button>' +
    '</div>';
  showAlert('⭐ सेवा को रेट करें', html);
};

window.setProRating = function(n){
  currentRating = n;
  document.querySelectorAll('#proStars span').forEach(function(s){
    s.style.color = (+s.dataset.s <= n) ? '#f5a623' : '#ccc';
  });
  var em = document.getElementById('proRateEmoji');
  if(em) em.innerHTML = PRO_RATE_EMOJI[n] || '';
};

window.proRateChip = function(el){
  el.classList.toggle('on');
  var t = document.getElementById('proRateCmt');
  if(!t) return;
  var tag = el.innerText.trim();
  if(el.classList.contains('on')){
    t.value = (t.value ? t.value + ' ' : '') + tag + '.';
  } else {
    t.value = t.value.replace(tag + '.', '').replace(/\s{2,}/g,' ').trim();
  }
};

/* ---------- SUBMIT: review + PARTNER ke data me save ---------- */
window.submitProRating = function(oid){
  var cmt = (document.getElementById('proRateCmt') ? document.getElementById('proRateCmt').value : '').trim();
  // 🔒 फोन नहीं, uid. reviews public हैं.
  var by = getUID() || 'anon';
  showLoader('रिव्यू सेव हो रहा है...');
  FS.collection('orders').doc(oid).get().then(function(d){
    var o = d.exists ? d.data() : {};
    var partnerPh = String(o.partnerPhone || PRO_PARTNER_PHONE);
    /* 🔒 partner का फोन भी नहीं जाता — partnerUid से पहचान होती है.
       order में partnerUid है तो वही, वरना कुछ नहीं (पुराने orders के लिए). */
    var pUid = (o && o.partnerUid) ? o.partnerUid : '';
    var review = { orderId: oid, rating: currentRating, comment: cmt, by: by,
                   partnerUid: pUid, ts: Date.now(), at: new Date().toLocaleString('en-IN') };
    var pref = FS.collection('partners').doc(partnerPh);
    return Promise.all([
      FS.collection('reviews').add(review),
      pref.collection('reviews').add(review),
      pref.set({
        phone: partnerPh, name: 'SewaAstra Partner',
        ratingSum: firebase.firestore.FieldValue.increment(currentRating),
        ratingCount: firebase.firestore.FieldValue.increment(1),
        lastReview: review
      }, {merge:true}),
      FS.collection('orders').doc(oid).update({ rated: true, rating: currentRating, ratedBy: by })
    ]).then(function(){
      /* average nikaal ke partner doc me save */
      return pref.get().then(function(pd){
        var p = pd.data() || {};
        if(p.ratingCount) return pref.update({ avgRating: Math.round((p.ratingSum / p.ratingCount) * 10) / 10 });
      });
    });
  }).then(function(){
    hideLoader(); closeCustomAlert();
    showToast('⭐ धन्यवाद! रेटिंग partner के प्रोफाइल में सेव हो गई 🎉');
  }).catch(function(e){ hideLoader(); showAlert('त्रुटि', e.message); });
};

/* ---------- ADMIN ORDERS: DELETE BUTTON ---------- */
window.adminDeleteOrder = function(oid){
  swUi.confirm({icon:'🗑️',title:'ऑर्डर delete करें?',msg:'ऑर्डर ' + oid + ' को हमेशा के लिए delete करना है?\n(Chat history भी हट जाएगी)',ok:'हाँ, delete करें',cancel:'रुकें',danger:true,onOk:function(){
    FS.collection('orders').doc(oid).delete()
      .then(function(){ showToast('🗑️ ऑर्डर ' + oid + ' delete हो गया'); })
      .catch(function(e){ showAlert('त्रुटि', e.message); });
  }});
};
(function(){
  var _rao = window.renderAdminOrders;
  window.renderAdminOrders = function(orders){
    _rao(orders);
    try{
      var list = document.getElementById('admOrdersList');
      if(!list) return;
      var cards = list.children;
      for(var i = 0; i < cards.length && i < orders.length; i++){
        if(cards[i].querySelector('.pro-adm-del')) continue;
        var b = document.createElement('button');
        b.className = 'pro-adm-del';
        b.innerHTML = '🗑️ इस ऑर्डर को Delete करें';
        b.setAttribute('onclick', "adminDeleteOrder('" + orders[i].id + "')");
        cards[i].appendChild(b);
      }
    }catch(e){}
  };
})();

console.log('%c SewaAstra v2.6 ✅ scroll-fix | auto-rating→partner | admin-delete ', 'background:#f5a623;color:#000;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 12 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([12, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 13 ═══ */
try {
/* ═══════════ SEWAASTRA v27 — PWA ENGINE ═══════════ */
(function(){
  /* SW register (https ya localhost par chalega) */
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').then(function(reg){
      console.log('✅ SW registered:', reg.scope);
      /* current page ko cache karwao — offline me yahi khulega */
      function cachePage(){
        if (navigator.serviceWorker.controller) {
          navigator.serviceWorker.controller.postMessage({ type:'CACHE_PAGE', url: location.href });
        }
      }
      if (navigator.serviceWorker.controller) cachePage();
      navigator.serviceWorker.addEventListener('controllerchange', cachePage);
      /* naya version aaya to batao */
      reg.addEventListener('updatefound', function(){
        var nw = reg.installing;
        if (!nw) return;
        nw.addEventListener('statechange', function(){
          if (nw.state === 'installed' && navigator.serviceWorker.controller) {
            showToast('🔄 App का नया version तैयार है — दोबारा खोलने पर मिलेगा');
          }
        });
      });
    }).catch(function(e){ console.log('SW fail:', e.message); });
  }

  /* OFFLINE / ONLINE indicator bar */
  document.body.insertAdjacentHTML('beforeend', '<div id="proNetBar"></div>');
  var bar = document.getElementById('proNetBar');
  window.addEventListener('offline', function(){
    bar.className = 'off';
    bar.innerHTML = '📴 आप Offline हैं — App cached mode में चल रहा है';
  });
  window.addEventListener('online', function(){
    bar.className = 'on';
    bar.innerHTML = '✅ Internet वापस आ गया!';
    setTimeout(function(){ bar.className = ''; }, 2500);
  });

  /* manifest shortcuts: ?view=orders / ?view=cart */
  window.addEventListener('load', function(){
    var v = new URLSearchParams(location.search).get('view');
    if (!v) return;
    setTimeout(function(){
      if (localStorage.getItem('sw_logged') !== 'true') return;
      if (v === 'orders' && typeof showHistory === 'function') showHistory();
      if (v === 'cart' && typeof checkout === 'function') { try{ checkout(); }catch(e){} }
    }, 2000);
  });
})();
console.log('%c SewaAstra v2.7 ✅ REAL PWA — manifest | sw | offline ', 'background:#ff6b00;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 13 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([13, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 14 ═══ */
try {
/* ═══════════ SEWAASTRA v28 — SPEED ENGINE ═══════════
   1. Leaflet lazy-load (map khulne par hi download)
   2. Unsplash images auto-compress (600px, q60)
   3. Sab images lazy + async decode
*/

/* ---------- 1. LEAFLET ON-DEMAND ---------- */
window.proLeafletReady = null;
window.proEnsureLeaflet = function(){
  if (window.L) return Promise.resolve();
  if (window.proLeafletReady) return window.proLeafletReady;
  showLoader('Map लोड हो रहा है...');
  window.proLeafletReady = new Promise(function(res, rej){
    var css = document.createElement('link');
    css.rel = 'stylesheet';
    css.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
    document.head.appendChild(css);
    var s = document.createElement('script');
    s.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    s.onload = function(){ hideLoader(); res(); };
    s.onerror = function(){ hideLoader(); window.proLeafletReady = null; rej(new Error('Map load failed')); };
    document.head.appendChild(s);
  });
  return window.proLeafletReady;
};
(function(){
  var _omm = window.openMapModal;
  if (typeof _omm === 'function'){
    window.openMapModal = function(){
      var a = arguments;
      proEnsureLeaflet().then(function(){ _omm.apply(null, a); })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    };
  }
  var _olt = window.openLiveTracking;
  if (typeof _olt === 'function'){
    window.openLiveTracking = function(oid){
      proEnsureLeaflet().then(function(){ _olt(oid); })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    };
  }
})();

/* ---------- 2 & 3. IMAGE SPEED OPTIMIZER ---------- */
function proFastenImg(im){
  if (im.dataset.proFast) return;
  im.dataset.proFast = '1';
  /* lazy + async decode */
  if (!im.hasAttribute('loading')) im.setAttribute('loading', 'lazy');
  if (!im.hasAttribute('decoding')) im.setAttribute('decoding', 'async');
  /* Unsplash: full-size ke bajaye 600px compressed version */
  var src = im.getAttribute('src') || '';
  if (src.indexOf('images.unsplash.com') > -1 && src.indexOf('w=') === -1){
    im.src = src + (src.indexOf('?') > -1 ? '&' : '?') + 'auto=format&fit=crop&w=600&q=60';
  }
}
function proFastenAll(root){
  (root || document).querySelectorAll('#display img, #bannerCarouselArea img, .card img').forEach(proFastenImg);
  /* pehla banner eager rakho (turant dikhe) */
  var first = document.querySelector('#bannerCarouselArea img');
  if (first) first.setAttribute('loading', 'eager');
}
new MutationObserver(function(){ proFastenAll(); })
  .observe(document.body, { childList: true, subtree: true });
proFastenAll();

/* idle time me tracking-modal ke tiles ka DNS warm karo */
if ('requestIdleCallback' in window){
  requestIdleCallback(function(){
    ['https://a.tile.openstreetmap.org','https://b.tile.openstreetmap.org'].forEach(function(h){
      var l = document.createElement('link'); l.rel = 'dns-prefetch'; l.href = h;
      document.head.appendChild(l);
    });
  });
}

console.log('%c SewaAstra v2.8 ⚡ SPEED ENGINE — lazy leaflet | fast images ', 'background:#e6f7ed;color:#0f7a37;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 14 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([14, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 15 ═══ */
try {
/* ═══════════ SEWAASTRA v29 MEGA ═══════════
   1. Shimmer skeletons  2. Language engine  3. Coupon celebration
   4. Bill + UPI QR (78699691901)  5. Online = payment-first order
*/

/* ---------- 1. SHIMMER SKELETONS ---------- */
var PRO_SK_CARD = '<div class="pro-sk-card pro-sk-tmp"><div class="pro-sk pro-sk-img"></div><div style="flex:1;"><div class="pro-sk pro-sk-l1"></div><div class="pro-sk pro-sk-l2"></div><div class="pro-sk pro-sk-l3"></div></div></div>';
function proSkeletonHome(){
  var d = document.getElementById('display');
  if (d && !d.querySelector('.card') && !d.querySelector('.pro-sk-tmp'))
    d.innerHTML = PRO_SK_CARD + PRO_SK_CARD + PRO_SK_CARD + PRO_SK_CARD;
  var b = document.getElementById('bannerCarouselArea');
  if (b && !b.querySelector('img') && !b.querySelector('.pro-sk-tmp'))
    b.innerHTML = '<div class="pro-sk pro-sk-banner pro-sk-tmp" style="min-width:100%;"></div>';
}
proSkeletonHome();
function proSkList(n){
  var h = '';
  for (var i = 0; i < (n || 3); i++) h += '<div class="pro-sk pro-sk-row"></div>';
  return '<div style="padding:4px 0;">' + h + '</div>';
}

/* ---------- 2. LANGUAGE ENGINE (pura app) ---------- */
var PRO_I18N = {
  en: {
    'सुप्रभात 🌞':'Good Morning 🌞','नमस्ते 👋':'Hello 👋','शुभ संध्या 🌙':'Good Evening 🌙',
    'आपका कार्ट खाली है':'Your cart is empty','कोई भी सर्विस चुनें — expert घर आएगा!':'Pick any service — expert comes home!',
    '🛠️ Services देखें':'🛠️ Browse Services','विकल्प चुनें (Select Option):':'Select Option:',
    'कुल कीमत':'Total Price','🛒 कार्ट में जोड़ें':'🛒 Add to Cart','✨ सर्विस विवरण':'✨ Service Details',
    'हमारे expert का काम कैसा रहा?':'How was our expert\u2019s work?','⭐ रिव्यू सबमिट करें':'⭐ Submit Review',
    'अपना अनुभव लिखें...':'Write your experience...','मोबाइल नंबर दर्ज करें':'Enter mobile number',
    'पता':'Address','तारीख':'Date','समय':'Time','भुगतान':'Payment','कुल':'Total','छूट':'Discount',
    'भाषा बदली गई!':'Language changed!','सेवा को रेट करें':'Rate the Service',
    '📲 App डाउनलोड करें':'📲 Download App','कूपन लग गया! 🎉':'Coupon Applied! 🎉',
    'बधाई हो!':'Congratulations!','मेरे ऑर्डर':'My Orders','इतिहास':'History','होम':'Home','सहायता':'Support'
  },
  bh: {
    'सुप्रभात 🌞':'सुप्रभात 🌞','नमस्ते 👋':'प्रणाम 🙏','शुभ संध्या 🌙':'शुभ साँझ 🌙',
    'आपका कार्ट खाली है':'रउरा कार्ट खाली बा','कोई भी सर्विस चुनें — expert घर आएगा!':'कवनो सर्विस चुनीं — एक्सपर्ट घरे आई!',
    '🛠️ Services देखें':'🛠️ सर्विस देखीं','कुल कीमत':'कुल दाम','🛒 कार्ट में जोड़ें':'🛒 कार्ट में जोड़ीं',
    'हमारे expert का काम कैसा रहा?':'हमार एक्सपर्ट के काम कइसन रहल?','⭐ रिव्यू सबमिट करें':'⭐ रिव्यू भेजीं',
    'अपना अनुभव लिखें...':'आपन अनुभव लिखीं...','भाषा बदली गई!':'भाषा बदल गइल!','मेरे ऑर्डर':'हमार ऑर्डर'
  },
  pb: {
    'सुप्रभात 🌞':'ਸ਼ੁਭ ਸਵੇਰ 🌞','नमस्ते 👋':'ਸਤ ਸ੍ਰੀ ਅਕਾਲ 🙏','शुभ संध्या 🌙':'ਸ਼ੁਭ ਸ਼ਾਮ 🌙',
    'आपका कार्ट खाली है':'ਤੁਹਾਡਾ ਕਾਰਟ ਖਾਲੀ ਹੈ','कोई भी सर्विस चुनें — expert घर आएगा!':'ਕੋਈ ਵੀ ਸਰਵਿਸ ਚੁਣੋ — ਐਕਸਪਰਟ ਘਰ ਆਵੇਗਾ!',
    '🛠️ Services देखें':'🛠️ ਸਰਵਿਸਾਂ ਵੇਖੋ','कुल कीमत':'ਕੁੱਲ ਕੀਮਤ','🛒 कार्ट में जोड़ें':'🛒 ਕਾਰਟ ਵਿੱਚ ਪਾਓ',
    'हमारे expert का काम कैसा रहा?':'ਸਾਡੇ ਐਕਸਪਰਟ ਦਾ ਕੰਮ ਕਿਵੇਂ ਰਿਹਾ?','⭐ रिव्यू सबमिट करें':'⭐ ਰਿਵਿਊ ਭੇਜੋ',
    'अपना अनुभव लिखें...':'ਆਪਣਾ ਤਜਰਬਾ ਲਿਖੋ...','भाषा बदली गई!':'ਭਾਸ਼ਾ ਬਦਲ ਗਈ!','मेरे ऑर्डर':'ਮੇਰੇ ਆਰਡਰ'
  }
};
function proApplyLang(){
  var lang = (typeof currentLang !== 'undefined' && (currentLang==='hi'||currentLang==='en')) ? currentLang : 'hi';
  var dict = PRO_I18N[lang];
  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  var n;
  while ((n = walker.nextNode())){
    var t = n.nodeValue.trim();
    if (!t) continue;
    if (n.__hi === undefined && lang !== 'hi' && dict && dict[t]) n.__hi = n.nodeValue;
    if (lang === 'hi'){ if (n.__hi !== undefined) n.nodeValue = n.__hi; }
    else if (dict){
      var base = (n.__hi !== undefined) ? n.__hi.trim() : t;
      if (dict[base]) n.nodeValue = n.nodeValue.replace(t, dict[base]);
    }
  }
  document.querySelectorAll('input[placeholder],textarea[placeholder]').forEach(function(el){
    var p = el.getAttribute('placeholder');
    if (!el.__hiP && lang !== 'hi') el.__hiP = p;
    if (lang === 'hi'){ if (el.__hiP) el.setAttribute('placeholder', el.__hiP); }
    else if (dict){ var b = el.__hiP || p; if (dict[b]) el.setAttribute('placeholder', dict[b]); }
  });
}
(function(){
  var _sl = window.setLang;
  window.setLang = function(l, ev){ _sl(l, ev); setTimeout(proApplyLang, 60); };
  var t = null;
  /* v25: auto-translate band - bhasha sirf aapke button dabane par badlegi */
  window.addEventListener('load', function(){
    var saved = localStorage.getItem('sw_lang');
    if (saved && saved !== 'hi' && PRO_I18N[saved]) setTimeout(proApplyLang, 1500);
  });
})();

/* ---------- 3. COUPON CELEBRATION 🎉 ---------- */
window.proCelebrate = function(amount){
  var wrap = document.getElementById('proConfettiWrap');
  if (!wrap){
    document.body.insertAdjacentHTML('beforeend',
      '<div id="proConfettiWrap"></div><div id="proCelebCard"><div class="big">🎉</div><div style="font-weight:900;font-size:15px;">कूपन लग गया!</div><div class="amt">₹' + amount + ' बचे!</div><div style="font-size:11px;opacity:.9;">बधाई हो!</div></div>');
    wrap = document.getElementById('proConfettiWrap');
  }
  document.querySelector('#proCelebCard .amt').innerText = '₹' + amount + ' बचे!';
  var colors = ['#ff6b00','#15a04a','#f5a623','#0d6efd','#e91e63','#9c27b0','#00bcd4'];
  var bits = '';
  for (var i = 0; i < 75; i++){
    bits += '<span class="pro-cf" style="left:' + (Math.random()*100) + 'vw;background:' + colors[i%colors.length] +
      ';animation-duration:' + (1.7+Math.random()*1.6) + 's;animation-delay:' + (Math.random()*0.5) + 's;width:' + (6+Math.random()*7) + 'px;"></span>';
  }
  wrap.innerHTML = bits; wrap.style.display = 'block';
  var card = document.getElementById('proCelebCard');
  card.classList.add('show');
  try{ if (navigator.vibrate) navigator.vibrate([60,40,60]); }catch(e){}
  setTimeout(function(){ card.classList.remove('show'); }, 2300);
  setTimeout(function(){ wrap.style.display = 'none'; wrap.innerHTML = ''; }, 3600);
};
(function(){
  var _ac = window.applyCoupon;
  if (typeof _ac === 'function'){
    window.applyCoupon = function(){
      var before = appliedDiscount;
      _ac();
      if (appliedDiscount > 0 && appliedDiscount !== before) proCelebrate(appliedDiscount);
    };
  }
})();

/* ---------- QR LIB (on-demand) ---------- */
window.proQRReady = null;
function proEnsureQR(){
  if (window.QRCode) return Promise.resolve();
  if (window.proQRReady) return window.proQRReady;
  window.proQRReady = new Promise(function(res, rej){
    var s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    s.onload = res;
    s.onerror = function(){ window.proQRReady = null; rej(new Error('QR lib load failed')); };
    document.head.appendChild(s);
  });
  return window.proQRReady;
}
var PRO_PHONEPE_MID = 'M23X4SPWMNOL8';   /* PhonePe Merchant ID */
function proUpiId(){ return (CLOUD_CONFIG && CLOUD_CONFIG.upiId) ? CLOUD_CONFIG.upiId : 'shoorshyam.vishwakarma@ibl'; }
function proUpiLink(amt, note, scheme){
  var ref = 'SW' + Date.now().toString().slice(-8);
  return (scheme || 'upi') + '://pay?pa=' + encodeURIComponent(proUpiId()) + '&pn=SewaAstra&am=' + amt + '&cu=INR&tn=' + encodeURIComponent(note || 'SewaAstra') + '&tr=' + ref;
}
function proMakeQR(el, text){
  el.innerHTML = '';
  proEnsureQR().then(function(){
    new QRCode(el, { text: text, width: 170, height: 170, correctLevel: QRCode.CorrectLevel.M });
  }).catch(function(){ el.innerHTML = '<div style="font-size:11px;color:#999;">QR load nahi hua — UPI button use karein</div>'; });
}

/* ---------- 4. BILL / INVOICE + QR ---------- */
window.__proBillRate = null;
window.proShowBill = function(oid, thenRate){
  window.__proBillRate = thenRate ? oid : null;
  var m = document.getElementById('proBillModal');
  if (!m){
    document.body.insertAdjacentHTML('beforeend', '<div id="proBillModal" onclick="if(event.target===this)proCloseBill()"><div class="pro-bill" id="proBillInner"></div></div>');
    m = document.getElementById('proBillModal');
  }
  var pO = FS.collection('orders').doc(oid).get();
  var pC = FS.collection('config').doc('global').get().catch(function(){ return null; });
  Promise.all([pO, pC]).then(function(r){
    var d = r[0];
    if (!d.exists) return showAlert('त्रुटि', 'ऑर्डर नहीं मिला');
    var o = d.data();
    var cfg = (r[1] && r[1].exists) ? r[1].data() : {};
    var gstPct = Math.max(0, Number(cfg.gstPct) || 0);
    var paid = !!(o.payment && (o.payment.verified || /^paid/i.test(o.payment.status || '')));
    var verifying = !!(o.payment && !paid && /verifying/i.test(o.payment.status || ''));
    var isCash = /cash|cod|नकद/i.test(o.mode || '');
    var cashCol = !!(o.payment && o.payment.cash);
    var sub = Number(o.subtotal) || (o.items || []).reduce(function(s, it){ return s + (Number(it.p)||0) * (it.qty||1); }, 0);
    var disc = Number(o.discount) || 0;
    var base = Math.max(0, sub - disc);
    var gstAmt = Math.round(base * gstPct / 100);
    var rows = (o.items || []).map(function(it){
      return '<tr><td>' + proEsc(it.n) + ' × ' + (it.qty||1) + '</td><td class="tr">₹' + ((Number(it.p)||0)*(it.qty||1)) + '</td></tr>';
    }).join('');
    window.__proBillTxt = '🧾 *SewaAstra Bill*%0A🆔 ' + oid + '%0A' + (o.items||[]).map(function(i){ return '• ' + i.n + ' x' + (i.qty||1) + ' = ₹' + ((Number(i.p)||0)*(i.qty||1)); }).join('%0A') + (gstPct>0 ? ('%0AGST (' + gstPct + '%): ₹' + gstAmt) : '') + '%0A💰 Total: ₹' + o.total + '%0A' + (paid ? '✅ PAID' : '⏳ Payment Due');
    /* payment status block */
    var payBlock = '';
    if (paid){
      if (isCash && cashCol) payBlock = '<div style="text-align:center;background:#e6f7ed;border:1px solid #a8e6c2;border-radius:12px;padding:11px;margin-top:10px;font-weight:900;color:#0f7a37;font-size:13px;">💵 Cash ले लिया गया — धन्यवाद!</div>';
      else payBlock = '<div style="text-align:center;background:#e6f7ed;border:1px solid #a8e6c2;border-radius:12px;padding:11px;margin-top:10px;font-weight:900;color:#0f7a37;font-size:13px;">✅ भुगतान हो चुका है' + (o.payment && o.payment.ref ? '<br><span style="font-size:10px;font-weight:700;">Ref: ' + proEsc(o.payment.ref) + '</span>' : '') + '</div>';
    } else if (verifying){
      payBlock = '<div style="text-align:center;background:#fff8e6;border:1px solid #ffe1a0;border-radius:12px;padding:13px;margin-top:10px;font-weight:900;color:#b07800;font-size:12.5px;">⏳ Payment Verification में है' + (o.payment && o.payment.ref ? '<br><span style="font-size:10px;font-weight:700;">UTR: ' + proEsc(o.payment.ref) + '</span>' : '') + '<br><span style="font-size:10px;font-weight:700;">Admin जल्द confirm करेंगे ✅</span></div>';
    } else if (isCash){
      payBlock = '<div style="text-align:center;background:#fff8e6;border:1.5px solid #ffd970;border-radius:12px;padding:12px;margin-top:10px;font-weight:900;color:#8a6100;font-size:12.5px;">💵 Cash (COD) — भुगतान partner को service के बाद दें<br><span style="font-size:10px;font-weight:700;">यह ऑर्डर cash का है — QR/UPI ज़रूरी नहीं</span></div>';
    } else {
      payBlock = '<div style="text-align:center;margin-top:8px;">' +
        '<div style="font-size:12px;font-weight:900;color:#ff6b00;">📲 UPI से भुगतान करें — Scan QR</div>' +
        '<div id="proQrBox"></div>' +
        '<div style="font-size:11px;color:#888;">UPI ID: <b>' + proEsc(proUpiId()) + '</b></div>' +
        '<a href="' + proUpiLink(o.total, oid, 'phonepe') + '" style="display:inline-block;margin:8px 3px 0;background:linear-gradient(90deg,#5f259f,#7b3fc4);color:#fff;padding:11px 18px;border-radius:12px;text-decoration:none;font-weight:900;font-size:12.5px;">💜 PhonePe ₹' + o.total + '</a>' +
        '<a href="' + proUpiLink(o.total, oid) + '" style="display:inline-block;margin:8px 3px 0;background:linear-gradient(90deg,#15a04a,#1fc25e);color:#fff;padding:11px 18px;border-radius:12px;text-decoration:none;font-weight:900;font-size:12.5px;">💳 अन्य UPI</a>' +
      '</div>';
    }
    document.getElementById('proBillInner').innerHTML =
      '<div class="pro-bill-head">' +
        '<span class="st" style="background:' + (paid?'#1fc25e':(verifying?'#b07800':(isCash?'#e58600':'#f5a623'))) + ';color:#fff;">' + (paid?'✅ PAID':(verifying?'⏳ VERIFYING':(isCash?'💵 CASH':'⏳ DUE'))) + '</span>' +
        '<div style="font-size:19px;font-weight:900;">🛠️ SewaAstra</div>' +
        '<div style="font-size:11px;opacity:.85;">TAX INVOICE / BILL</div>' +
        '<div style="font-size:11px;margin-top:6px;">🆔 <b>' + proEsc(oid) + '</b> &nbsp;•&nbsp; 📅 ' + proEsc(o.timestamp || (o.date + ' ' + (o.time||''))) + '</div>' +
        '<div style="font-size:11px;">👤 ' + proEsc(o.mobile||'') + '</div>' +
      '</div>' +
      '<div style="padding:14px 16px;">' +
        '<table>' + rows +
          '<tr><td>Subtotal</td><td class="tr">₹' + sub + '</td></tr>' +
          (gstPct > 0 ? '<tr><td>GST (' + gstPct + '%) <span style="color:#999;font-weight:700;">(included)</span></td><td class="tr" style="color:#7b1fa2;">₹' + gstAmt + '</td></tr>' : '') +
          (disc ? '<tr><td style="color:#15a04a;">छूट (Coupon)</td><td class="tr" style="color:#15a04a;">−₹' + disc + '</td></tr>' : '') +
          '<tr><td>Visit Charge</td><td class="tr">₹10</td></tr>' +
          '<tr><td style="font-size:15px;font-weight:900;border:none;">कुल (Total' + (gstPct>0?' • GST incl':'') + ')</td><td class="tr" style="font-size:17px;color:#15a04a;border:none;">₹' + o.total + '</td></tr>' +
        '</table>' +
        payBlock +
        '<div style="display:flex;gap:8px;margin-top:14px;">' +
          '<button class="pro-bill-btn" style="background:#0d6efd;color:#fff;" onclick="proPrintBill(\'' + oid + '\')">🖨️ Print / PDF</button>' +
          '<button class="pro-bill-btn" style="background:#25d366;color:#fff;" onclick="window.open(\'https://wa.me/?text=\'+window.__proBillTxt,\'_blank\')">📤 Share</button>' +
          '<button class="pro-bill-btn" style="background:#eee;color:#555;" onclick="proCloseBill()">बंद करें</button>' +
        '</div>' +
      '</div>';
    m.classList.add('open');
    var showQr = !paid && !isCash;
    if (showQr){
      var qb = document.getElementById('proQrBox');
      if (qb) proMakeQR(qb, proUpiLink(o.total, oid));
    }
  }).catch(function(e){ showAlert('त्रुटि', e.message); });
};

window.proCloseBill = function(){
  document.getElementById('proBillModal').classList.remove('open');
  if (window.__proBillRate){
    var oid = window.__proBillRate; window.__proBillRate = null;
    setTimeout(function(){ openRateModal(oid); }, 450);
  }
};
window.proPrintBill = function(oid){
  var inner = document.getElementById('proBillInner');
  var w = window.open('', '_blank', 'noopener,noreferrer');
  w.document.write('<html><head><title>SewaAstra Bill ' + oid + '</title><style>body{font-family:sans-serif;max-width:420px;margin:20px auto;}table{width:100%;border-collapse:collapse;font-size:13px;}td{padding:6px 0;border-bottom:1px dashed #ccc;}.tr{text-align:right;font-weight:bold;}.pro-bill-head{background:#0b1220;color:#fff;padding:16px;border-radius:12px;}button,a{display:none!important;}img,canvas{display:block!important;margin:10px auto;}</style></head><body>' + inner.innerHTML + '<p style="text-align:center;font-size:11px;color:#888;">धन्यवाद! SewaAstra — आपकी सेवा में 🙏</p></body></html>');
  w.document.close();
  setTimeout(function(){ w.print(); }, 600);
};

/* kaam COMPLETE → pehle BILL, phir RATING (v2.6 watcher upgrade) */
function proStartRatingWatcher(){
  try{
    if (typeof isAdminUser === 'function' && isAdminUser()) return;
    if (!getUID() && !getIdent()) return;
    if (window.__proRateUnsub) window.__proRateUnsub();
    window.__proRateUnsub = myOrdersQuery().onSnapshot(function(snap){
      snap.docChanges().forEach(function(ch){
        var o = ch.doc.data();
        if (o.status === 'Completed' && !o.rated && !proRatePrompted[o.id]){
          proRatePrompted[o.id] = true;
          if (ch.type === 'modified'){
            showToast('🎉 काम पूरा! आपका बिल तैयार है');
            setTimeout(function(){ proShowBill(o.id, true); }, 900);
          } else if (ch.type === 'added'){
            setTimeout(function(){ openRateModal(o.id); }, 2500);
          }
        }
      });
    }, function(e){ console.warn('rate watch:', e.message); });
  }catch(e){}
}

/* ---------- 5. ONLINE = PAYMENT PEHLE, ORDER BAAD ME ---------- */
function proOpenPayment(amt, onDone){
  var m = document.getElementById('proPayModal');
  if (!m){
    document.body.insertAdjacentHTML('beforeend', '<div id="proPayModal"><div class="pro-pay" id="proPayInner"></div></div>');
    m = document.getElementById('proPayModal');
  }
  document.getElementById('proPayInner').innerHTML =
    '<div style="background:linear-gradient(120deg,#0b1220,#123);color:#fff;padding:16px;border-radius:20px 20px 0 0;">' +
      '<div style="font-weight:900;font-size:15px;">💳 पहले भुगतान करें</div>' +
      '<div style="font-size:11px;opacity:.85;">Payment के बाद ही ऑर्डर place होगा</div>' + '<div style="font-size:10px;opacity:.7;margin-top:3px;">💜 PhonePe Merchant: ' + PRO_PHONEPE_MID + '</div></div>' +
    '<div class="pro-pay-amt" style="margin-top:12px;">₹' + amt + '</div>' +
    '<div id="proPayQr" style="display:flex;justify-content:center;margin:8px 0;"></div>' +
    '<div style="font-size:11.5px;color:#888;">UPI ID: <b>' + proEsc(proUpiId()) + '</b></div>' +
    '<a href="' + proUpiLink(amt, 'SewaAstra Order', 'phonepe') + '" class="pro-pay-link" style="display:inline-block;margin:10px 4px 4px;background:linear-gradient(90deg,#5f259f,#7b3fc4);color:#fff;padding:12px 22px;border-radius:12px;text-decoration:none;font-weight:900;font-size:13.5px;box-shadow:0 8px 20px rgba(95,37,159,.4);">💜 PhonePe से Pay करें</a>' +
    '<a href="' + proUpiLink(amt, 'SewaAstra Order') + '" class="pro-pay-link" style="display:inline-block;margin:10px 4px 4px;background:linear-gradient(90deg,#15a04a,#1fc25e);color:#fff;padding:12px 22px;border-radius:12px;text-decoration:none;font-weight:900;font-size:13.5px;box-shadow:0 8px 20px rgba(21,160,74,.35);">📲 अन्य UPI App</a>' +
    '<div class="pro-pay-step"><b>1.</b> QR scan करें या ऊपर के button से PhonePe/GPay/Paytm में pay करें</div>' +
    '<div class="pro-pay-step"><b>2.</b> Payment के बाद <b>UTR / Transaction ID डालना ज़रूरी है</b> — तभी order खुलेगा</div>' +
    '<input id="proPayRef" placeholder="UTR / Transaction ID (ज़रूरी) *" style="width:calc(100% - 32px);margin:6px 16px;border:1.5px solid var(--border-color,#ddd);border-radius:10px;padding:11px;font-size:13px;background:var(--card-bg);color:var(--text);">' +
    '<div id="proPayLock" style="margin:10px 16px 0;background:#f4f0ec;border:1.5px dashed #d9cfc4;border-radius:12px;padding:12px;font-size:12px;font-weight:800;color:#998;display:flex;align-items:center;justify-content:center;gap:7px;">🔒 पहले ऊपर से Payment पूरा करें — फिर Order button यहाँ खुलेगा</div>' +
    '<div id="proPayWait" style="display:none;margin:10px 16px 0;background:#fff5ed;border:1.5px dashed #ffb066;border-radius:12px;padding:12px;font-size:12px;font-weight:800;color:#e85a0c;">⏳ Payment check हो रहा है... UPI app से वापस आइए</div>' +
    '<div id="proPayBtnRow" style="display:none;gap:8px;margin:10px 16px 0;">' +
      '<button id="proPayDoneBtn" style="flex:2;background:linear-gradient(90deg,#15a04a,#1fc25e);color:#fff;border:none;border-radius:12px;padding:14px;font-weight:900;font-size:13px;cursor:pointer;box-shadow:0 8px 22px rgba(21,160,74,.4);animation:instPop .45s cubic-bezier(.2,.9,.3,1.2), instGlow 1.8s ease-in-out infinite;">✅ Payment हो गया — Order Place करें</button>' +
    '</div>' +
    '<div style="display:flex;margin:8px 16px 0;">' +
      '<button id="proPayCancelBtn" style="flex:1;background:transparent;color:#999;border:1.5px solid var(--border-color,#e5e5e5);border-radius:12px;padding:11px;font-weight:800;font-size:12px;cursor:pointer;">रद्द करें</button>' +
    '</div>';
  m.classList.add('open');
  proMakeQR(document.getElementById('proPayQr'), proUpiLink(amt, 'SewaAstra Order'));

  /* ── payment-complete detection: pay tap → UPI app → wapas → Order button popup ── */
  var payAttempted = false, unlocked = false;
  function proUnlockOrder(){
    if (unlocked) return;
    unlocked = true;
    document.getElementById('proPayLock').style.display = 'none';
    document.getElementById('proPayWait').style.display = 'none';
    document.getElementById('proPayBtnRow').style.display = 'flex';
    try{ if (navigator.vibrate) navigator.vibrate([80,50,80]); }catch(e){}
    showToast('✅ अब Order Place कर सकते हैं!');
  }
  function proAskUTR(){
    var w = document.getElementById('proPayWait');
    w.style.display = 'block';
    w.innerHTML = '🧾 Payment हो गया? अब नीचे <b>UTR / Transaction ID</b> डालें — उसके बाद ही Order button खुलेगा';
    var inp = document.getElementById('proPayRef');
    inp.style.borderColor = '#ff6b00';
    inp.style.boxShadow = '0 0 0 3px rgba(255,107,0,.18)';
    inp.focus();
  }
  document.querySelectorAll('#proPayInner .pro-pay-link').forEach(function(a){
    a.addEventListener('click', function(){
      payAttempted = true;
      document.getElementById('proPayLock').style.display = 'none';
      document.getElementById('proPayWait').style.display = 'block';
      setTimeout(function(){ if (payAttempted && !unlocked) proAskUTR(); }, 12000);
    });
  });
  /* UPI app se wapas → UTR required (auto-unlock NAHI) */
  function proVisBack(){
    if (document.visibilityState === 'visible' && payAttempted && !unlocked){
      setTimeout(proAskUTR, 600);
    }
  }
  document.addEventListener('visibilitychange', proVisBack);
  /* UTR verify: 10+ chars → verifying → tab Order button popup */
  var verTimer = null;
  document.getElementById('proPayRef').addEventListener('input', function(){
    var v = this.value.trim().replace(/\s/g, '');
    clearTimeout(verTimer);
    if (v.length >= 10 && !unlocked){
      var w = document.getElementById('proPayWait');
      w.style.display = 'block';
      w.innerHTML = '⏳ UTR <b>' + v.slice(0,4) + '…' + v.slice(-4) + '</b> verify हो रहा है...';
      verTimer = setTimeout(proUnlockOrder, 1600);
    }
  });

  document.getElementById('proPayDoneBtn').onclick = function(){
    var ref = (document.getElementById('proPayRef').value || '').trim();
    if (ref.replace(/\s/g, '').length < 10) return showAlert('UTR ज़रूरी है', 'कृपया UPI app से 12-अंकों का UTR / Transaction ID copy करके डालें — तभी order place होगा।');
    document.removeEventListener('visibilitychange', proVisBack);
    m.classList.remove('open');
    onDone(ref);
  };
  document.getElementById('proPayCancelBtn').onclick = function(){
    document.removeEventListener('visibilitychange', proVisBack);
    m.classList.remove('open');
    showToast('भुगतान रद्द — ऑर्डर place नहीं हुआ');
  };
}

window.handleFinalOrder = function(){
  var _extraEl = document.getElementById('proAddrExtra');
  var _extra = _extraEl ? _extraEl.value.trim() : '';
  var _area = document.getElementById('manualAddr').value.trim();
  var address = (_extra ? _extra + ', ' : '') + _area;
  try{ localStorage.setItem('sw_addr_line', _area); localStorage.setItem('sw_addr_extra', _extra); }catch(e){}
  var mobile = document.getElementById('altMobile').value.trim();
  var date = document.getElementById('cartDate').value;
  var time = document.getElementById('cartTime').value;
  var remark = document.getElementById('cartRemark').value.trim();
  var mapsLink = document.getElementById('googleMapsLink').value;
  if (!address) return showAlert('पता आवश्यक है', 'कृपया अपनी डिलीवरी लोकेशन या पता दर्ज करें');
  if (!selectedMode) return showAlert('भुगतान मोड चुनें', 'कृपया Cash या Online भुगतान का तरीका चुनें');
  if (!cart.length) return showAlert('कार्ट खाली है', 'पहले कोई सेवा जोड़ें');
  var subtotal = cart.reduce(function(a, c){ return a + (c.p * (c.qty||1)); }, 0);
  var finalAmt = (subtotal - appliedDiscount) + 10;
  if (finalAmt < 10) finalAmt = 10;

  function placeOrder(payment){
    var oid = 'SW' + Math.floor(100000 + Math.random() * 900000);
    var userMobile = mobile || getIdent() || '';
    var order = {
      id: oid, uid: getUID(), mobile: userMobile,
      items: cart.map(function(i){ return { n:i.n, p:i.p, qty:i.qty||1, cat:i.cat||'', catName:i.catName||'' }; }),
      subtotal: subtotal, discount: appliedDiscount, total: finalAmt,
      address: address, date: date, time: time, remark: remark,
      mode: selectedMode, maps: mapsLink || '',
      cats: (function(){ var s={},out=[]; (cart||[]).forEach(function(i){ var k=i.cat||'general', nn=i.catName||'General'; if(!s[k]){s[k]=1; out.push({key:k,name:nn});} }); return out; })(),
      status: 'Order Placed', rated: false, payment: payment,
      loc: (typeof userCoords !== 'undefined' ? { lat:userCoords.lat, lon:userCoords.lon } : null),
      createdAt: Date.now(), timestamp: new Date().toLocaleString('hi-IN')
    };
    showLoader('ऑर्डर सेव हो रहा है...');
    FS.collection('orders').doc(oid).set(order).then(function(){
      hideLoader();
      var hist = JSON.parse(localStorage.getItem('sw_order_history')) || [];
      hist.unshift(order);
      localStorage.setItem('sw_order_history', JSON.stringify(hist.slice(0, 50)));
      var waMsg = '*🚀 New SewaAstra Booking!*%0A🆔 Order ID: ' + oid + '%0A👤 User: ' + userMobile +
        '%0A📦 Items: ' + cart.map(function(i){ return i.n + ' (x' + (i.qty||1) + ')'; }).join(', ') +
        '%0A💰 Total: ₹' + finalAmt + ' (' + selectedMode + (payment && /verifying/i.test(payment.status||'') ? ' — 💳 UTR: ' + payment.ref + ' ⚠️VERIFY करें' : (payment && /paid/i.test(payment.status||'') ? ' — PAID ✅' : '')) + ')' +
        '%0A📍 Address: ' + address + '%0A🗺️ Map: ' + mapsLink + '%0A📅 ' + date + ' at ' + time + '%0A📝 ' + (remark || 'None');
      closeCart(); cart = [];
      try{ renderCart(); }catch(e){}
      document.getElementById('bCount').innerText = '0';
      appliedDiscount = 0;
      var payLine = (payment && payment.verified)
        ? '<br><span style="color:#15a04a;font-weight:800;">✅ भुगतान सफल — ₹' + finalAmt + '</span>'
        : (payment && /verifying/i.test(payment.status||''))
        ? '<br><span style="color:#b07800;font-weight:800;">⏳ Payment verification में — UTR: ' + proEsc(payment.ref||'') + '<br>Admin जल्द confirm करेंगे</span>'
        : '';
      showAlert('बुकिंग सफल! 🎉', 'आपका ऑर्डर <b>' + oid + '</b> ☁️ cloud में सेव हो गया है!' + payLine + '<br>स्टेटस अपडेट 📋 History में मिलेंगे।<br><br>WhatsApp पर विवरण भेजा जा रहा है...');
      setTimeout(function(){ window.open('https://wa.me/917869969190?text=' + waMsg, '_blank', 'noopener,noreferrer'); }, 1800);
      startMyOrdersListener();
      proStartRatingWatcher();
    }).catch(function(e){ hideLoader(); showAlert('त्रुटि', 'ऑर्डर सेव नहीं हो सका: ' + e.message); });
  }

  if (selectedMode === 'Online'){
    proOpenPayment(finalAmt, function(ref){
      placeOrder({ method:'UPI', status:'Payment Verifying', verified:false, ref: ref || '', paidAt: Date.now(), upi: proUpiId(), gateway:'PhonePe', mid: PRO_PHONEPE_MID });
    });
  } else {
    placeOrder({ method:'Cash', status:'Pay after service' });
  }
};

/* ---------- HISTORY v3: skeleton + 🧾 Bill button ---------- */
window.showHistory = function(){
  showAlert('📋 मेरे ऑर्डर (Live)', proSkList(3));
  myOrdersQuery().get().then(function(snap){
    var orders = snap.docs.map(function(d){ return d.data(); });
    if (!orders.length) return showAlert('ऑर्डर इतिहास', 'अभी तक कोई ऑर्डर नहीं है।');
    orders.sort(function(a,b){ return (b.createdAt||0) - (a.createdAt||0); });
    var doneCnt = orders.filter(function(o){ return ['Completed','Cancelled'].indexOf(o.status) > -1; }).length;
    var html = '<div style="text-align:left; max-height:65vh; overflow-y:auto;">';
    if (doneCnt) html += '<button onclick="clearMyHistory()" style="width:100%;background:#fdecea;color:#e53935;border:1.5px dashed #f5c6c3;border-radius:12px;padding:10px;font-weight:800;font-size:12px;cursor:pointer;margin-bottom:12px;">🗑️ पूरी History साफ़ करें (' + doneCnt + ' पुराने ऑर्डर)</button>';
    orders.forEach(function(o){
      var clr = STATUS_CLR[o.status] || '#666';
      var canCancel = ['Order Placed','Accepted'].indexOf(o.status) > -1;
      var canRate = o.status === 'Completed' && !o.rated;
      var canDel = ['Completed','Cancelled'].indexOf(o.status) > -1;
      var paid = o.payment && (o.payment.verified || /^paid/i.test(o.payment.status || ''));
      var verifying = o.payment && !paid && /verifying/i.test(o.payment.status || '');
      html += '<div style="background:var(--card-bg); border:1px solid var(--border-color); padding:14px; border-radius:14px; margin-bottom:12px; box-shadow:0 4px 12px rgba(13,30,60,.06);">' +
        '<div style="display:flex; justify-content:space-between; align-items:center; font-weight:800; font-size:14px;">' +
          '<span style="color:var(--primary);">' + o.id + '</span>' +
          '<span style="background:' + clr + '22;color:' + clr + ';padding:3px 10px;border-radius:12px;font-size:11px;">' + (STATUS_HI[o.status] || o.status) + '</span></div>' +
        '<div style="font-size:12px; color:#888; margin:4px 0;">📅 ' + proEsc(o.date) + ' | ⏰ ' + proEsc(o.time) + ' | <b style="color:#15a04a;">₹' + o.total + '</b> (' + o.mode + (paid ? ' ✅PAID' : (verifying ? ' ⏳Verifying' : '')) + ')</div>' +
        '<div style="font-size:12px; margin:4px 0;">📍 ' + proEsc(o.address) + '</div>' +
        '<div style="font-size:12px; font-weight:700; margin-top:4px;">🛠️ ' + (o.items||[]).map(function(i){ return proEsc(i.n) + ' (x' + (i.qty||1) + ')'; }).join(', ') + '</div>' +
        (o.rated ? '<div style="font-size:12px;color:#f5a623;font-weight:800;margin-top:4px;">⭐ आपने रेटिंग दे दी है</div>' : '') +
        '<div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap;">' +
          '<button onclick="openLiveTracking(\'' + o.id + '\')" style="flex:1;min-width:84px;background:var(--primary);color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">🗺️ Tracking</button>' +
          '<button onclick="openOrderChat(\'' + o.id + '\')" style="flex:1;min-width:70px;background:#0d6efd;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">💬 Chat</button>' +
          '<button onclick="proShowBill(\'' + o.id + '\')" style="flex:1;min-width:70px;background:#0b1220;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">🧾 Bill</button>' +
          (canRate ? '<button onclick="openRateModal(\'' + o.id + '\')" style="flex:1;min-width:70px;background:#f5a623;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">⭐ Rate</button>' : '') +
          (canCancel ? '<button onclick="cancelMyOrder(\'' + o.id + '\')" style="flex:1;min-width:70px;background:#e53935;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:800;cursor:pointer;">❌ Cancel</button>' : '') +
          (canDel ? '<button class="pro-hist-del" onclick="deleteMyOrder(\'' + o.id + '\')" title="Delete">🗑️</button>' : '') +
        '</div></div>';
    });
    html += '</div>';
    showAlert('📋 मेरे ऑर्डर (Live)', html);
  }).catch(function(e){ showAlert('त्रुटि', e.message); });
};

console.log('%c SewaAstra v2.9 🚀 skeleton | i18n | celebration | bill+QR | pay-first ', 'background:#e91e63;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 15 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([15, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 16 ═══ */
try {
/* ═══════════ SEWAASTRA v32 ═══════════
   1. Admin: Payment Verify button (UTR ke saath)
   2. Rating par click → saare reviews dekho
*/

/* ---------- 1. ADMIN PAYMENT VERIFY ---------- */
window.adminVerifyPayment = function(oid, ref){
  swUi.confirm({icon:'💜',title:'Payment VERIFY करें?',msg:'PhonePe Business app me check kiya?\nUTR: ' + (ref||'—') + '\n\nPayment VERIFY karein?',ok:'✅ Verify करें',cancel:'रुकें',onOk:function(){
    FS.collection('orders').doc(oid).update({
      'payment.verified': true,
      'payment.status': 'PAID (Admin Verified)',
      'payment.verifiedAt': Date.now()
    }).then(function(){ showToast('✅ Payment verified — ' + oid); })
      .catch(function(e){ showAlert('त्रुटि', e.message); });
  }});
};
(function(){
  var _rao = window.renderAdminOrders;
  window.renderAdminOrders = function(orders){
    _rao(orders);
    try{
      var list = document.getElementById('admOrdersList');
      if(!list) return;
      var cards = list.children;
      for(var i = 0; i < cards.length && i < orders.length; i++){
        var o = orders[i];
        if(!o.payment || cards[i].querySelector('.pro-paystat')) continue;
        var p = o.payment;
        var verified = p.verified || /^paid/i.test(p.status||'');
        var verifying = !verified && /verifying/i.test(p.status||'');
        var tag = verified
          ? '<span class="pro-paystat" style="background:#e6f7ed;color:#0f7a37;">✅ PAID' + (p.ref ? ' • UTR: ' + proEsc(p.ref) : '') + '</span>'
          : verifying
          ? '<span class="pro-paystat" style="background:#fff8e6;color:#b07800;">⏳ Verify करना बाकी • UTR: ' + proEsc(p.ref||'—') + '</span>'
          : '<span class="pro-paystat" style="background:#f4f0ec;color:#888;">💵 ' + proEsc(p.status||'Cash') + '</span>';
        var del = cards[i].querySelector('.pro-adm-del');
        var host = document.createElement('div');
        host.innerHTML = tag + (verifying ? '<button class="pro-verify-btn" onclick="adminVerifyPayment(\'' + SWSec.esc(String(o.id||'').replace(/[^A-Za-z0-9_-]/g,'')) + '\',\'' + proEsc(p.ref||'') + '\')">💜 PhonePe में UTR check करके Payment VERIFY करें</button>' : '');
        if(del) cards[i].insertBefore(host, del); else cards[i].appendChild(host);
      }
    }catch(e){}
  };
})();

/* customer ko verify hone par turant khabar */
var proPayVerNotified = {};
function proStartPayVerWatcher(){
  try{
    if (typeof isAdminUser === 'function' && isAdminUser()) return;
    if (!getUID() && !getIdent()) return;
    if (window.__proPayVerUnsub) window.__proPayVerUnsub();
    window.__proPayVerUnsub = myOrdersQuery().onSnapshot(function(snap){
      snap.docChanges().forEach(function(ch){
        var o = ch.doc.data();
        if (ch.type === 'modified' && o.payment && o.payment.verified && !proPayVerNotified[o.id]){
          proPayVerNotified[o.id] = true;
          showToast('✅ आपका Payment VERIFY हो गया — Order ' + o.id + ' 🎉');
          try{ if (navigator.vibrate) navigator.vibrate([70,40,70]); }catch(e){}
        }
        if (o.payment && o.payment.verified) proPayVerNotified[o.id] = true;
      });
    }, function(e){});
  }catch(e){}
}
firebase.auth().onAuthStateChanged(function(u){ if(u) setTimeout(proStartPayVerWatcher, 2200); });
window.addEventListener('load', function(){
  if (localStorage.getItem('sw_logged') === 'true') setTimeout(proStartPayVerWatcher, 3500);
});

/* ---------- 2. RATING CLICK → REVIEWS VIEWER ---------- */
function proMaskUser(s){
  s = String(s || '');
  if (s.indexOf('@') > -1) return s.slice(0,3) + '***@' + s.split('@')[1];
  if (s.length >= 10) return s.slice(0,2) + '******' + s.slice(-2);
  return s || 'ग्राहक';
}
window.proShowReviews = function(){
  showAlert('⭐ Ratings & Reviews', proSkList(3));
  Promise.all([
    FS.collection('partners').doc(PRO_PARTNER_PHONE).get(),
    FS.collection('reviews').orderBy('ts', 'desc').limit(30).get()
  ]).then(function(res){
    var pd = res[0].exists ? res[0].data() : {};
    var revs = res[1].docs.map(function(d){ return d.data(); });
    var cnt = pd.ratingCount || revs.length;
    var avg = pd.avgRating || (revs.length ? Math.round(revs.reduce(function(a,r){ return a + (r.rating||0); }, 0) / revs.length * 10) / 10 : 0);
    if (!cnt && !revs.length)
      return showAlert('⭐ Ratings & Reviews', '<div style="text-align:center;padding:20px;"><div style="font-size:44px;">🌟</div><div style="font-weight:900;margin-top:8px;">अभी कोई review नहीं</div><div style="font-size:12px;color:#888;margin-top:4px;">पहली service के बाद यहाँ reviews दिखेंगे</div></div>');
    var dist = {1:0,2:0,3:0,4:0,5:0};
    revs.forEach(function(r){ if(dist[r.rating] !== undefined) dist[r.rating]++; });
    var bars = '';
    for (var s = 5; s >= 1; s--){
      var pc = revs.length ? Math.round(dist[s] / revs.length * 100) : 0;
      bars += '<div style="display:flex;align-items:center;gap:7px;font-size:10.5px;font-weight:800;color:#888;margin-top:3px;"><span style="width:22px;">' + s + '★</span><div class="pro-rev-bar"><span style="width:' + pc + '%;"></span></div><span style="width:30px;">' + dist[s] + '</span></div>';
    }
    var html = '<div style="text-align:left;max-height:65vh;overflow-y:auto;">' +
      '<div class="pro-rev-top">' +
        '<div style="text-align:center;"><div class="pro-rev-avg">' + avg + '</div>' +
        '<div class="pro-rev-stars">' + '★'.repeat(Math.round(avg)) + '<span style="color:#ddd;">' + '★'.repeat(5-Math.round(avg)) + '</span></div>' +
        '<div style="font-size:10px;color:#888;font-weight:800;">' + cnt + ' reviews</div></div>' +
        '<div style="flex:1;">' + bars + '</div>' +
      '</div>';
    revs.forEach(function(r){
      var d = r.at || (r.ts ? new Date(r.ts).toLocaleDateString('hi-IN') : '');
      html += '<div class="pro-rev-card">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;">' +
          '<span class="pro-rev-stars">' + '★'.repeat(r.rating||0) + '<span style="color:#ddd;">' + '★'.repeat(5-(r.rating||0)) + '</span></span>' +
          '<span style="font-size:10px;color:#999;">' + proEsc(d) + '</span></div>' +
        (r.comment ? '<div style="font-size:12.5px;margin-top:5px;line-height:1.5;">' + proEsc(r.comment) + '</div>' : '') +
        '<div style="font-size:10.5px;color:#999;margin-top:5px;font-weight:700;">👤 ' + proEsc(proMaskUser(r.by)) + (r.orderId ? ' • ' + proEsc(r.orderId) : '') + '</div>' +
      '</div>';
    });
    html += '</div>';
    showAlert('⭐ Ratings & Reviews', html);
  }).catch(function(e){ showAlert('त्रुटि', e.message); });
};
/* har rating par click → reviews */
document.body.addEventListener('click', function(e){
  if (e.target.closest('.rating-row') || e.target.closest('.svc-hero .sub')) proShowReviews();
});

/* cards par REAL avg rating dikhana (Firebase se) */
function proPaintAvg(){
  if (!window.__proAvgTxt) return;
  document.querySelectorAll('.rating-val').forEach(function(el){ el.innerText = window.__proAvgTxt; });
  document.querySelectorAll('.review-count').forEach(function(el){ el.innerText = '(' + window.__proAvgCnt + ' reviews)'; });
}
window.addEventListener('load', function(){
  setTimeout(function(){
    FS.collection('partners').doc(PRO_PARTNER_PHONE).get().then(function(d){
      if (d.exists && d.data().avgRating){
        window.__proAvgTxt = d.data().avgRating;
        window.__proAvgCnt = d.data().ratingCount || 0;
        proPaintAvg();
        var t = null;
        new MutationObserver(function(){ clearTimeout(t); t = setTimeout(proPaintAvg, 300); })
          .observe(document.getElementById('display') || document.body, { childList:true, subtree:true });
      }
    }).catch(function(){});
  }, 2500);
});

console.log('%c SewaAstra v3.2 ✅ pay-verify | reviews-viewer ', 'background:#b07800;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 16 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([16, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 17 ═══ */
try {
/* ═══════════ SEWAASTRA v33 — SMART LOCATION ═══════════
   1. Jagah badalte hi header me area ka naam LIVE update
   2. GPS/Map se cart me "Area, City - PIN" auto-fill
   3. Additional address alag field + agli baar auto-yaad
*/

/* ---------- REVERSE GEOCODE helper ---------- */
function proRevGeo(lat, lon){
  return fetch('https://nominatim.openstreetmap.org/reverse?format=json&addressdetails=1&lat=' + lat + '&lon=' + lon)
    .then(function(r){ return r.json(); })
    .then(function(d){
      var a = d.address || {};
      var area = a.neighbourhood || a.suburb || a.hamlet || a.quarter || a.residential || a.road || a.village || '';
      var city = a.city || a.town || a.village || a.state_district || a.county || '';
      var pin  = a.postcode || '';
      var line = [area, city].filter(Boolean).join(', ') + (pin ? ' - ' + pin : '');
      return { area: area || city || 'Current Location', city: city, pin: pin, line: line || 'Current Location' };
    });
}

/* ---------- 2. GPS button → Area + PIN auto-fill ---------- */
window.getLiveLocation = function(){
  showLoader('लोकेशन प्राप्त की जा रही है...');
  if (!navigator.geolocation){ hideLoader(); return showAlert('त्रुटि', 'GPS उपलब्ध नहीं है।'); }
  navigator.geolocation.getCurrentPosition(function(pos){
    hideLoader();
    userCoords.lat = pos.coords.latitude;
    userCoords.lon = pos.coords.longitude;
    document.getElementById('googleMapsLink').value = 'https://www.google.com/maps?q=' + userCoords.lat + ',' + userCoords.lon;
    proRevGeo(userCoords.lat, userCoords.lon).then(function(g){
      document.getElementById('manualAddr').value = g.line;
      document.getElementById('locTxt').innerText = g.area;
      window.__proLastArea = g.area;
      try{ localStorage.setItem('sw_addr_line', g.line); }catch(e){}
      showToast('📍 ' + g.line + ' सेट हो गया!');
      var ex = document.getElementById('proAddrExtra');
      if (ex && !ex.value) ex.focus();
    }).catch(function(){
      document.getElementById('manualAddr').value = 'GPS Location (' + userCoords.lat.toFixed(3) + ', ' + userCoords.lon.toFixed(3) + ')';
      document.getElementById('locTxt').innerText = 'लोकेशन सेट ✅';
      showToast('GPS लोकेशन मिल गई! 📍');
    });
  }, function(){
    hideLoader();
    showAlert('लोकेशन त्रुटि', 'लोकेशन अनुमति दें या मैप से चुनें।');
  }, { enableHighAccuracy: true, timeout: 12000 });
};

/* ---------- Map pin confirm → bhi area+PIN ---------- */
window.confirmMapLocation = function(){
  document.getElementById('googleMapsLink').value = 'https://www.google.com/maps?q=' + userCoords.lat + ',' + userCoords.lon;
  closeMapModal();
  showLoader('जगह का नाम निकाला जा रहा है...');
  proRevGeo(userCoords.lat, userCoords.lon).then(function(g){
    hideLoader();
    document.getElementById('manualAddr').value = g.line;
    document.getElementById('locTxt').innerText = g.area;
    window.__proLastArea = g.area;
    try{ localStorage.setItem('sw_addr_line', g.line); }catch(e){}
    showToast('📍 ' + g.line + ' कन्फर्म!');
  }).catch(function(){
    hideLoader();
    document.getElementById('manualAddr').value = 'Map Pin: ' + userCoords.lat.toFixed(4) + ', ' + userCoords.lon.toFixed(4);
    document.getElementById('locTxt').innerText = 'मैप सेट ✅';
    showToast('मैप लोकेशन कन्फर्म हो गई!');
  });
};

/* ---------- 1. LIVE WATCH: jagah badli → header me naya area ---------- */
function proDist(a1, o1, a2, o2){
  var R = 6371000, dLat = (a2-a1) * Math.PI/180, dLon = (o2-o1) * Math.PI/180;
  var x = Math.sin(dLat/2) * Math.sin(dLat/2) + Math.cos(a1*Math.PI/180) * Math.cos(a2*Math.PI/180) * Math.sin(dLon/2) * Math.sin(dLon/2);
  return R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1-x));
}
var proLastGeo = { lat: 0, lon: 0, ts: 0 };
function proStartLocWatch(){
  if (!navigator.geolocation || window.__proLocWatch) return;
  window.__proLocWatch = navigator.geolocation.watchPosition(function(pos){
    var la = pos.coords.latitude, lo = pos.coords.longitude;
    userCoords.lat = la; userCoords.lon = lo;
    var now = Date.now();
    /* 150m+ move + 20s gap → naya area naam laao */
    if (proDist(proLastGeo.lat, proLastGeo.lon, la, lo) > 150 && now - proLastGeo.ts > 20000){
      proLastGeo = { lat: la, lon: lo, ts: now };
      proRevGeo(la, lo).then(function(g){
        var el = document.getElementById('locTxt');
        if (el) el.innerText = g.area;
        if (window.__proLastArea && window.__proLastArea !== g.area){
          showToast('📍 अब आप ' + g.area + ' में हैं');
        }
        window.__proLastArea = g.area;
      }).catch(function(){});
    }
  }, function(){}, { enableHighAccuracy: false, maximumAge: 25000, timeout: 20000 });
}
window.addEventListener('load', function(){
  setTimeout(function(){
    if (localStorage.getItem('sw_logged') === 'true') proStartLocWatch();
  }, 4000);
});

/* ---------- 3. Cart khulte hi saved address auto-fill ---------- */
(function(){
  var _co = window.checkout;
  if (typeof _co !== 'function') return;
  window.checkout = function(){
    _co();
    try{
      var m = document.getElementById('manualAddr');
      var e = document.getElementById('proAddrExtra');
      if (m && !m.value.trim() && localStorage.getItem('sw_addr_line')) m.value = localStorage.getItem('sw_addr_line');
      if (e && !e.value.trim() && localStorage.getItem('sw_addr_extra')) e.value = localStorage.getItem('sw_addr_extra');
    }catch(x){}
  };
})();

console.log('%c SewaAstra v3.3 📍 live area | auto PIN | extra address ', 'background:#0d6efd;color:#fff;font-weight:bold;padding:4px;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 17 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([17, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 18 ═══ */
try {
/* v3.4 — customer ONLINE presence (partner app ko dikhta hai) */
function proHeartbeat(on){
  try{
    var id = (localStorage.getItem('sw_user')||'').trim();
    var uu=''; try{ uu=firebase.auth().currentUser?firebase.auth().currentUser.uid:''; }catch(e){}
    if(!id || localStorage.getItem('sw_logged')!=='true') return;
    if(uu){ FS.collection('presence').doc(uu).set({uid:uu,phone:id,lastSeen: Date.now(), online: on!==false}, {merge:true}).catch(function(){}); }
  }catch(e){}
}
window.addEventListener('load', function(){ setTimeout(function(){ proHeartbeat(true); }, 3000); });
setInterval(function(){ if(document.visibilityState==='visible') proHeartbeat(true); }, 45000);
document.addEventListener('visibilitychange', function(){ proHeartbeat(document.visibilityState==='visible'); });
window.addEventListener('pagehide', function(){ proHeartbeat(false); });
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 18 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([18, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 19 ═══ */
try {
/* ═══════════ CUSTOMER LOGIN FIX v3.5 ═══════════ */
function proAuthErr(e){
  var c = (e && e.code) || '';
  var host = location.hostname || '(file)';
  var M = {
    'auth/unauthorized-domain': '🌐 यह domain Firebase में allowed नहीं!<br><br>Console → Authentication → Settings → <b>Authorized domains</b> में add करें:<br><b>' + host + '</b>',
    'auth/billing-not-enabled': '💳 Email/Password login के लिए Blaze ज़रूरी नहीं — Console → Authentication → Sign-in method में <b>Email/Password</b> enable करें।',
    'auth/invalid-app-credential': '🤖 reCAPTCHA fail — page reload करें, domain authorized check करें।',
    'auth/captcha-check-failed': '🤖 reCAPTCHA verify नहीं हुआ — domain authorize करके reload करें।',
    'auth/too-many-requests': '⏳ बहुत कोशिशें — थोड़ी देर बाद try करें।',
    'auth/operation-not-allowed': '⚙️ Console → Authentication → Sign-in method में <b>Email/Password</b> व Google दोनों enable करें।',
    'auth/operation-not-supported-in-this-environment': '🌐 यह browser/preview login support नहीं करता — https hosting पर खोलें।',
    'auth/network-request-failed': '📶 Internet problem।'
  };
  return (M[c] || proEsc(e.message || String(e))) + '<br><small>(code: ' + c + ')</small>';
}

/* GOOGLE: popup block → redirect fallback */
function proGoogleDone(user){
  localStorage.setItem('sw_logged', 'true');
  var identifier = user.email || user.phoneNumber || 'Google User';
  localStorage.setItem('sw_user', identifier);
  checkAdminAccess(user.email || '');
  if (user.photoURL){
    localStorage.setItem('sw_user_photo', user.photoURL);
    document.getElementById('headerPic').src = user.photoURL;
    document.getElementById('sheetPic').src = user.photoURL;
  }
  document.getElementById('authOverlay').style.display = 'none';
  document.getElementById('googlePhonePromptOverlay').style.display = 'flex';
  checkAndShowInstallModalAfterLogin();
  showToast('Google से लॉगिन सफल! अब मोबाइल नंबर दर्ज करें।');
}
window.loginWithGoogle = function(){
  showLoader('Google से लॉगिन हो रहा है...');
  var prov = new firebase.auth.GoogleAuthProvider();
  firebase.auth().signInWithPopup(prov).then(function(r){
    hideLoader(); proGoogleDone(r.user);
  }).catch(function(e){
    hideLoader();
    var c = e.code || '';
    if (['auth/popup-blocked','auth/cancelled-popup-request','auth/operation-not-supported-in-this-environment','auth/web-storage-unsupported'].indexOf(c) > -1){
      showToast('Popup block — redirect से login हो रहा है...');
      firebase.auth().signInWithRedirect(prov).catch(function(e2){ showAlert('लॉगिन त्रुटि', proAuthErr(e2)); });
    } else showAlert('लॉगिन त्रुटि', proAuthErr(e));
  });
};
firebase.auth().getRedirectResult().then(function(r){
  if (r && r.user) proGoogleDone(r.user);
}).catch(function(e){ if (e.code) showAlert('लॉगिन त्रुटि', proAuthErr(e)); });

/* PHONE OTP: robust + friendly errors */
window.sendRealPhoneOTP = function(){
  var phoneInput = document.getElementById('userPhone').value.trim();
  if (phoneInput.length !== 10) return showAlert('अमान्य नंबर', 'कृपया सही 10-अंकों का मोबाइल नंबर दर्ज करें');
  if (!window.recaptchaVerifier){
    try{ window.recaptchaVerifier = new firebase.auth.RecaptchaVerifier('recaptcha-container', { size:'invisible' }); }
    catch(e){ return showAlert('reCAPTCHA त्रुटि', proAuthErr(e)); }
  }
  showLoader('OTP भेजा जा रहा है...');
  firebase.auth().signInWithPhoneNumber('+91' + phoneInput, window.recaptchaVerifier)
    .then(function(confirmationResult){
      hideLoader();
      windowConfirmationResult = confirmationResult;
      localStorage.setItem('sw_user', phoneInput);
      document.getElementById('profilePhoneDisplay').innerText = '+91 ' + phoneInput;
      document.getElementById('phoneAuthSection').style.display = 'none';
      document.getElementById('otpAuthSection').style.display = 'block';
      showToast('मोबाइल पर असली OTP भेज दिया गया है! 📩');
    }).catch(function(e){
      hideLoader();
      try{ window.recaptchaVerifier.clear(); window.recaptchaVerifier = null; }catch(x){}
      showAlert('SMS OTP त्रुटि', proAuthErr(e));
    });
};

if (location.protocol === 'file:'){
  setTimeout(function(){
    showAlert('⚠️ File से खोला गया है', 'Login (Email/Password/Google) के लिए app को <b>hosting</b> पर खोलें:<br>• Firebase Hosting (free, सबसे सही)<br>• या localhost server<br><br>file:// पर Firebase login काम नहीं करता।');
  }, 2500);
}
console.log('%c CUSTOMER LOGIN FIX v3.5 ✅ ', 'background:#e53935;color:#fff;font-weight:bold;');
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 19 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([19, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 20 ═══ */
try {
/* v3.6 removed — REAL login only (OTP / Google). सब data Firebase realtime से। */
console.log('%c REAL AUTH MODE ✅ (Direct Login removed) ', 'background:#15a04a;color:#fff;font-weight:bold;');

/* ═══ CUSTOMER SOS v4.1 — 🆘 Emergency (112 / 108) + शिकायत — SUNDER POPUP ═══ */
(function(){
  if(window.__sos41) return; window.__sos41=1;
  var st=document.createElement('style');
  st.innerText=
  '#soSOv{position:fixed;inset:0;z-index:480000;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(40,4,4,.72);backdrop-filter:blur(6px)}'+
  '#soSOv.on{display:flex}'+
  '.sosb{width:100%;max-width:410px;border-radius:30px;overflow:hidden;background:#fff;color:#222;box-shadow:0 34px 110px rgba(0,0,0,.6);animation:sosIn .3s cubic-bezier(.2,1.25,.4,1)}'+
  'body.dark-mode .sosb{background:#221a16;color:#eee}'+
  '@keyframes sosIn{from{transform:scale(.9) translateY(16px);opacity:0}to{transform:none;opacity:1}}'+
  '.sosTop{background:linear-gradient(135deg,#c62828,#ff7043);color:#fff;text-align:center;padding:24px 14px 18px;position:relative}'+
  '.sosTop .ic{font-size:52px;line-height:1;filter:drop-shadow(0 5px 9px rgba(0,0,0,.4))}'+
  '.sosTop .t1{font-size:21px;font-weight:900;margin-top:8px;letter-spacing:.3px}'+
  '.sosTop .t2{font-size:11px;opacity:.95;font-weight:700;margin-top:3px}'+
  '.sosX{position:absolute;top:10px;right:12px;width:32px;height:32px;border-radius:50%;background:rgba(255,255,255,.25);border:none;color:#fff;font-size:16px;font-weight:900;cursor:pointer}'+
  '.sosBody{padding:16px 16px 20px}'+
  '.sosCall{display:flex;gap:10px;margin-bottom:6px}'+
  '.sosCall a{flex:1;text-decoration:none;border-radius:18px;padding:14px 8px;color:#fff;text-align:center;font-weight:900;display:block}'+
  '.sosCall .c1{background:linear-gradient(135deg,#0d47a1,#1e88e5);box-shadow:0 8px 20px rgba(13,71,161,.35)}'+
  '.sosCall .c2{background:linear-gradient(135deg,#b71c1c,#e53935);box-shadow:0 8px 20px rgba(183,28,28,.35)}'+
  '.sosCall a i{display:block;font-size:26px;font-style:normal;line-height:1}'+
  '.sosCall a b{display:block;font-size:22px;margin:4px 0 2px;letter-spacing:1px}'+
  '.sosCall a span{font-size:9.5px;opacity:.95;font-weight:800}'+
  '.sosInfo{font-size:10.5px;color:#b07800;background:#fff6e0;border:1px solid #ffe1a0;border-radius:12px;padding:8px 10px;margin:8px 0 14px;font-weight:800;line-height:1.6}'+
  'body.dark-mode .sosInfo{background:#3a2e14;color:#ffd970}'+
  '.sosDiv{display:flex;align-items:center;gap:8px;margin:12px 0 10px;color:#999;font-size:11px;font-weight:800}'+
  '.sosDiv::before,.sosDiv::after{content:"";flex:1;height:1px;background:#eee} body.dark-mode .sosDiv::before,body.dark-mode .sosDiv::after{background:#3a2f28}'+
  '.sosTA{width:100%;border:1.5px solid #eee;background:#fafafa;color:#222;border-radius:14px;padding:11px 12px;font-size:13px;min-height:74px;resize:none;outline:none;font-weight:600;box-sizing:border-box}'+
  'body.dark-mode .sosTA{background:#2b221c;color:#eee;border-color:#3a2f28}'+
  '.sosTA:focus{border-color:#e53935}'+
  '.sosSend{width:100%;border:none;border-radius:14px;padding:13px;background:linear-gradient(135deg,#ff6b00,#ff9a3d);color:#fff;font-weight:900;font-size:13px;cursor:pointer;margin-top:10px}'+
  '.sosPanic{width:100%;border:none;border-radius:14px;padding:14px;background:linear-gradient(135deg,#b71c1c,#ff5252);color:#fff;font-weight:900;font-size:13.5px;cursor:pointer;margin-top:6px;box-shadow:0 8px 20px rgba(229,57,53,.45);animation:sosBlink 1s infinite}'+
  '@keyframes sosBlink{50%{opacity:.72}}'
  '.sosSend:active{transform:scale(.98)}'+
  '.sosCls{width:100%;border:none;background:none;color:#999;font-weight:800;font-size:12px;padding:11px;cursor:pointer}'+
  '#cCOv{z-index:9999990!important}#cCeb{z-index:9999991!important}';
  document.head.appendChild(st);

  var ov=null;
  function ovr(){
    if(ov) return ov;
    ov=document.createElement('div'); ov.id='soSOv';
    ov.innerHTML=
      '<div class="sosb">'+
        '<div class="sosTop"><button class="sosX" onclick="cSosClose()">✕</button><div class="ic">🆘</div><div class="t1">Emergency / SOS</div><div class="t2">आपात स्थिति में तुरंत कॉल करें</div></div>'+
        '<div class="sosBody">'+
          '<div class="sosCall">'+
            '<a class="c1" href="tel:112"><i>🚓</i><b>112</b><span>Police / सभी आपात</span></a>'+
            '<a class="c2" href="tel:108"><i>🚑</i><b>108</b><span>Ambulance / Medical</span></a>'+
          '</div>'+
          '<div class="sosInfo">ℹ️ <b>112</b> — पुलिस/फायर/मेडिकल सभी आपात<br>ℹ️ <b>108</b> — एम्बुलेंस (बीमारी/दुर्घटना)</div>'+
          '<div class="sosDiv">या ऐप से मदद माँगें</div>'+
          '<textarea class="sosTA" id="sosMsg" placeholder="क्या हुआ? (जगह/समस्या लिखें) — Location अपने आप जुड़ जाएगी"></textarea>'+
          '<button class="sosPanic" onclick="cSosPanic()">🚨 EMERGENCY ALERT भेजें (Admin तक)</button>'+
          '<button class="sosSend" onclick="cSosSend()">📨 शिकायत / सुझाव दर्ज करें</button>'+
          '<button class="sosCls" onclick="cSosClose()">✕ बंद करें</button>'+
        '</div>'+
      '</div>';
    document.body.appendChild(ov);
    return ov;
  }
  window.cSosOpen=function(){
    var o=ovr(); o.classList.add('on');
    var ta=document.getElementById('sosMsg'); if(ta) ta.value='';
  };
  window.cSosClose=function(){ var o=ovr(); o.classList.remove('on'); };
  window.cSosPanic=function(){
    var ph=localStorage.getItem('sw_user')||'';
    if(!ph) return alert('पहले login करें — तभी alert आपके नंबर से जाएगा');
    var ta=document.getElementById('sosMsg');
    var m=(ta?ta.value:'').trim();
    if(m.length<4) m='🆘 Emergency — तुरंत मदद चाहिए';
    var nm='';
    try{ nm=localStorage.getItem('sw_user_name')||''; }catch(e){}
    var uid=''; try{ uid=firebase.auth().currentUser?firebase.auth().currentUser.uid:''; }catch(e){}
    var lastOrder=''; try{ var h=JSON.parse(localStorage.getItem('sw_order_history')||'[]'); if(h.length) lastOrder=h[0].id||''; }catch(e){}
    function fire(loc){
      var rec={type:'sos',kind:'emergency',phone:ph,name:nm,uid:uid,msg:m,
        orderId:lastOrder||'',ts:Date.now(),at:new Date().toLocaleString('en-IN'),status:'active'};
      if(loc) rec.loc={lat:loc.lat,lon:loc.lon};
      firebase.firestore().collection('sos_alerts').add(rec).then(function(d){
        window.cSosClose();
        showAlert('🚨 EMERGENCY ALERT भेज दिया गया!','Admin dashboard पर तुरंत 🔴 red alert + sound के साथ दिखेगा। वे आपको तुरंत कॉल करेंगे।<br><br>🆘 बहुत गंभीर हो तो <b>112</b> पर भी कॉल करें।');
        try{ window.open('https://wa.me/917869969190?text='+encodeURIComponent('🚨 SEWAASTRA EMERGENCY\n📱 '+ph+(nm?('\n👤 '+nm):'')+'\n📍 '+(loc?('lat:'+loc.lat+',lon:'+loc.lon):'GPS off')+'\n🗒️ '+SWSec.esc(m)+'\n🧾 Last order: '+(lastOrder||'-')),'_blank'); }catch(e){}
      }).catch(function(e){ showAlert('त्रुटि', e.message); });
    }
    try{
      navigator.geolocation.getCurrentPosition(function(p){ fire({lat:p.coords.latitude,lon:p.coords.longitude}); },
        function(){ fire(null); },{timeout:6000});
      setTimeout(function(){ },7000);
    }catch(e){ fire(null); }
  };
  window.cSosSend=function(){
    var ph=localStorage.getItem('sw_user')||'';
    if(!ph) return alert('पहले login करें');
    var ta=document.getElementById('sosMsg'); if(!ta) return;
    var m=(ta.value||'').trim();
    if(m.length<10) return alert('कृपया शिकायत थोड़ा detail में लिखें');
    var btn=document.querySelector('#soSOv .sosSend'); if(btn){ btn.disabled=true; btn.innerText='भेज रहे हैं...'; }
    var cuu=''; try{ cuu=firebase.auth().currentUser?firebase.auth().currentUser.uid:''; }catch(e){}
    firebase.firestore().collection('tickets').add({
      from:'customer', phone:ph, uid:cuu, name:'', cat:'🛒 Customer शिकायत',
      msg:m, status:'Open', ts:Date.now(), at:new Date().toLocaleString('en-IN')
    }).then(function(){
      alert('✅ शिकायत दर्ज हो गई!\nAdmin जल्द resolve करेंगे।');
      window.cSosClose();
    }).catch(function(e){
      alert('❌ '+e.message);
    }).finally(function(){
      var b2=document.querySelector('#soSOv .sosSend'); if(b2){ b2.disabled=false; b2.innerText='📨 शिकायत भेजें'; }
    });
  };
  function mkBtn(){
    if(document.getElementById('cmpBtn')){ var old=document.getElementById('cmpBtn'); old.onclick=function(){ window.cSosOpen(); }; return; }
    var b=document.createElement('div'); b.id='cmpBtn'; b.title='SOS / शिकायत';
    b.style.cssText='position:fixed;left:14px;bottom:92px;z-index:8000;width:46px;height:46px;border-radius:50%;background:linear-gradient(135deg,#c62828,#ff7043);color:#fff;display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 8px 20px rgba(229,57,53,.5);cursor:pointer;border:1.5px solid rgba(255,255,255,.35);';
    b.innerHTML='🆘';
    b.onclick=function(){ window.cSosOpen(); };
    document.body.appendChild(b);
  }
  window.addEventListener('load',function(){ setTimeout(mkBtn,1200); });
  /* purana onclick bhi baad me re-bind (agar pehle se button bana ho) */
  setTimeout(function(){ try{ if(document.getElementById('cmpBtn')) document.getElementById('cmpBtn').onclick=function(){ window.cSosOpen(); }; }catch(e){} },4000);
  console.log('%c 🆘 CUSTOMER SOS v4.1 — 112/108 SUNDER ✅ ','background:#c62828;color:#fff;font-weight:bold;padding:3px;');
})();


/* ═════ CUSTOMER COMPLETE-OTP v3.8N — काम पूरा पर NAYA OTP + 60s LIVE COUNTDOWN ═════ */
(function(){
  if(window.__c38n) return; window.__c38n=1;
  var watcher=null, curKey='', ovl=null, tick=null, gone=null, st=null;
  var stEl=null;
  if(!document.getElementById('wCmpSty')){
    st=document.createElement('style'); st.id='wCmpSty'; st.textContent=
      '@keyframes wcmpIn{from{transform:translate(-50%,16px);opacity:0}to{transform:translate(-50%,0);opacity:1}}'+
      '@keyframes wcmpPu{0%{transform:scale(1)}45%{transform:scale(1.05)}100%{transform:scale(1)}}';
    document.head.appendChild(st);
  }
  function killOld(){
    if(tick){ clearInterval(tick); tick=null; }
    if(gone){ clearTimeout(gone); gone=null; }
    if(ovl){ try{ ovl.remove(); }catch(e){} ovl=null; }
  }
  function card(code,dl){
    killOld(); curKey='';
    ovl=document.createElement('div'); ovl.id='wOtpBar';
    ovl.style.cssText='position:fixed;bottom:168px;left:50%;transform:translateX(-50%);z-index:8250;width:min(94vw,430px);background:linear-gradient(135deg,#12091f,#3a2008);border:1.5px solid #ffd60a;border-radius:22px;padding:14px 16px 13px;color:#fff;box-shadow:0 18px 48px rgba(0,0,0,.6);box-sizing:border-box;text-align:center;font-family:inherit;';
    ovl.style.animation='wcmpIn .3s ease';
    ovl.innerHTML=
      '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;text-align:left;">'+
        '<b style="font-size:12.5px;color:#ffe9b8;">🔐 काम पूरा — नया Completion OTP</b>'+
        '<span id="wCmpT" style="font-size:10px;font-weight:900;color:#ffd60a;border:1px solid #ffd60a;border-radius:20px;padding:3px 9px;white-space:nowrap;flex:0 0 auto;background:rgba(255,214,10,.08);">⏳ 1:00</span></div>'+
      '<div style="text-align:center;"><span id="wCmpN" style="font-size:36px;font-weight:900;letter-spacing:9px;color:#ffd60a;line-height:1.25;text-shadow:0 0 16px rgba(255,214,10,.4);animation:wcmpPu 1s ease infinite;">'+String(code).replace(/[^0-9]/g,'')+'</span></div>'+
      '<div style="height:8px;border-radius:10px;background:rgba(255,255,255,.14);overflow:hidden;margin:6px 0 9px;"><div id="wCmpB" style="height:100%;width:100%;border-radius:10px;background:linear-gradient(90deg,#2bc96e,#ffd60a,#ff6b00);"></div></div>'+
      '<div style="font-size:10px;color:#d9c9a8;font-weight:700;line-height:1.7;">यह OTP सिर्फ <b style="color:#ffd60a;">1 मिनट</b> valid है (timer गिन रहा है)। अपने काम वाले <b>partner को यह नंबर बताएँ</b> — वही इसे डालकर काम <b>"पूरा"</b> करेगा।<br>'+
      '<span style="color:#8a94ab;font-weight:600;">⏱ समय खत्म होगा तो partner दोबारा "काम पूरा" दबाकर नया OTP लेगा।</span></div>';
    document.body.appendChild(ovl);
    var num=document.getElementById('wCmpN'), tt=document.getElementById('wCmpT'), bb=document.getElementById('wCmpB');
    function paint(){
      var r=dl-Date.now();
      if(r<=0){
        if(tick){ clearInterval(tick); tick=null; }
        if(ovl&&ovl.isConnected){
          ovl.innerHTML='<div style="font-size:12px;font-weight:900;color:#ffb74d;line-height:1.8;">⌛ यह OTP <b>expire</b> हो गया (60s पूरे)<br><span style="font-size:9.5px;color:#aaa;font-weight:600;">partner "काम पूरा" दोबारा दबाएगा तो नया OTP आएगा</span></div>';
        }
        curKey='exp';
        if(!gone){ gone=setTimeout(function(){ if(ovl&&curKey==='exp'){ try{ ovl.remove(); }catch(e){} ovl=null; } gone=null; },7000); }
        return;
      }
      var s=Math.ceil(r/1000), mm=Math.floor(s/60), ss=s-mm*60;
      if(tt) tt.innerText='⏳ '+mm+':'+(ss<10?'0':'')+ss;
      if(bb) bb.style.width=Math.max(0,(r/60000)*100)+'%';
    }
    paint(); tick=setInterval(paint,500);
  }
  function resolve(snap){
    var cm=null, pw=null;
    snap.docs.forEach(function(d){
      var o=d.data();
      var active=['Accepted','On the Way','Working'].indexOf(o.status)>-1;
      if(o.cOtp&&o.status==='Working'){
        var at=Number(o.cOtpAt)||0;
        if(!cm||at>(cm.at||0)) cm={code:String(o.cOtp),at:at||Date.now(),oid:o.id||d.id};
      } else if(active&&o.wOtp&&!o.cOtp){
        if(!pw||(o.createdAt||0)>(pw.createdAt||0)) pw=o;
      }
    });
    if(cm){
      if(curKey!=='x'+cm.at){ curKey='x'+cm.at; card(cm.code,(cm.at||Date.now())+60000); }
      else if(curKey==='x'+cm.at&&tick){ /* already live */ }
      return;
    }
    killOld(); curKey='';
  }
  function boot(){
    var ph=localStorage.getItem('sw_user')||'';
    if(!ph){ setTimeout(boot,1500); return; }
    if(watcher) return;
    try{
      watcher=(SWID.orderQuery(FS,'customer')||firebase.firestore().collection('orders').where('mobile','==',ph).limit(100)).onSnapshot(resolve,function(){ setTimeout(boot,3000); watcher=null; });
    }catch(e){ setTimeout(boot,2000); }
  }
  setTimeout(boot,900);
  window.addEventListener('load',function(){ setTimeout(boot,1800); });
  console.log('%c 🔐 CUSTOMER v3.8N — COMPLETE OTP + 60s COUNTDOWN ✅ ','background:#8a5a00;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 20 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([20, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 21 ═══ */
try {
/* ═══════════════ CUSTOMER v3.9 — ADMIN BANNERS/NOTICE + BELL + CHAT ALERT DOT ═══════════════ */
(function(){
  if(window.__v39C) return; window.__v39C=1;
  var VG=['linear-gradient(135deg,#ff6b00,#ffa53d)','linear-gradient(135deg,#7b1fa2,#e91e63)','linear-gradient(135deg,#0d47a1,#00bcd4)','linear-gradient(135deg,#0f9d45,#2bc96e)','linear-gradient(135deg,#1a1030,#4a2408)','linear-gradient(135deg,#e53935,#ff9800)'];
  var VEM={'banner':'📢','offer':'🏷️','incentive':'🎁','notice':'📣','update':'🆕'};
  var VTX={'banner':'🪧 Banner','offer':'🛍️ Offer','incentive':'💰 Incentive','notice':'📣 Notice','update':'🆕 Update'};
  var v39B=[], v39Prev={}, v39Seen={}, v39U={}, v39Fs={};
  function es(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function ldS(){ try{ v39Seen=JSON.parse(localStorage.getItem('swc_bseen')||'{}'); }catch(e){ v39Seen={}; } }
  function svS(){ try{ localStorage.setItem('swc_bseen',JSON.stringify(v39Seen)); }catch(e){} }
  function gd(b){ var i=(b&&b.grad!=null)?Number(b.grad):0; return VG[i%VG.length]; }
  function em(b){ return (b&&b.emoji)?b.emoji:(VEM[b.type]||'📢'); }
  function rd(){ var d=document.getElementById('v39Bd'); if(!d) return;
    var n=0; v39B.forEach(function(b){ if(!v39Seen[b._id]) n++; });
    if(n>0){ d.style.display='flex'; d.innerText=n>9?'9+':n; } else d.style.display='none';
  }
  /* ─── DOM: bell + rail + sheets ─── */
  function mk(){
    if(document.getElementById('v39Bell')) return;
    var hp=document.getElementById('headerProfile');
    if(hp){ var bl=document.createElement('div'); bl.id='v39Bell'; bl.innerHTML='<i class="fa fa-bell"></i><span id="v39Bd"></span>'; bl.addEventListener('click',function(){ v39Open(); }); hp.parentNode.insertBefore(bl,hp); }
    var bc=document.getElementById('bannerCarouselArea');
    if(bc&&!document.getElementById('v39Rail')) bc.insertAdjacentHTML('beforebegin','<div id="v39Rail" class="v39r"></div>');
    if(!document.getElementById('v39Ov')){
      var ov=document.createElement('div'); ov.id='v39Ov';
      ov.innerHTML='<div class="v39sh"><div class="v39hh" style="justify-content:space-between;"><span>🔔 सूचनाएँ <span style="font-size:10px;color:#999;">(Admin से)</span></span><div><button onclick="v39AllRead()" style="border:1px solid #ddd;background:#f5f5f5;color:#333;border-radius:20px;padding:6px 13px;font-size:10.5px;font-weight:800;cursor:pointer;margin-right:6px;">सब पढ़ लिया</button><button onclick="v39CloseOv()" style="border:none;background:none;font-size:20px;cursor:pointer;color:#999;">✕</button></div></div><div class="v39list" id="v39List"></div></div>';
      document.body.appendChild(ov);
    }
    if(!document.getElementById('v39Bx')){
      var bx=document.createElement('div'); bx.id='v39Bx';
      bx.innerHTML='<div class="v39bx"><div class="v39bh" id="v39BxH" style="background:linear-gradient(135deg,#ff6b00,#ffa53d);"><button onclick="v39BxClose()">✕</button><div class="big" id="v39BxE">📢</div></div><div class="v39bb"><h3 id="v39BxT"></h3><p id="v39BxM"></p><div class="v39mg" id="v39BxMeta"></div><button class="v39go" style="background:linear-gradient(135deg,#ff6b00,#ffa53d);" onclick="v39BxClose()">ठीक है 👍</button></div></div>';
      document.body.appendChild(bx);
    }
    if(!document.getElementById('v39Pill')){
      var pl=document.createElement('div'); pl.id='v39Pill';
      pl.innerHTML='<span class="dot"></span><span id="v39PillT">💬 नया मैसेज — खोलें</span>';
      document.body.appendChild(pl);
    }
  }
  mk();
  function rail(){
    var r=document.getElementById('v39Rail'); if(!r) return;
    if(!v39B.length){ r.style.display='none'; return; }
    r.style.display='flex';
    r.innerHTML=v39B.slice(0,12).map(function(b){
      return '<div class="v39c" style="background:'+gd(b)+';" onclick="v39View(\''+b._id+'\')"><div class="e">'+em(b)+'</div><div class="t">'+es(b.title||'')+'</div><div class="s">'+es(String(b.msg||'').slice(0,100))+'</div><div class="k">'+es(VTX[b.type]||'Notice')+'</div></div>';
    }).join('');
  }
  /* ─── Listener ─── */
  var v39L=false;
  function listen(){
    if(v39L) return; v39L=true;
    try{
      firebase.firestore().collection('broadcasts').where('active','==',true).limit(30).onSnapshot(function(s){
        v39B=s.docs.map(function(d){ var b=d.data(); b._id=d.id; return b; }).filter(function(b){ var t=b.to||'all'; return t==='all'||t==='customer'; }).sort(function(a,b2){ return (b2.ts||0)-(a.ts||0); });
        v39B.forEach(function(b){
          if(!v39Prev[b._id]&&!v39Seen[b._id]){ try{ var t=document.getElementById('welcomeToast'); if(t){ t.innerText='📢 '+em(b)+' '+(b.title||'नया update!'); t.style.display='block'; setTimeout(function(){ t.style.display='none'; },3200); } }catch(e){} }
          v39Prev[b._id]=1;
        });
        rail(); rd(); v39List();
      },function(){});
    }catch(e){}
  }
  /* ─── Bell sheet ─── */
  function openList(){ v39List(); var ov=document.getElementById('v39Ov'); if(ov) ov.classList.add('open'); }
  function v39List(){
    var l=document.getElementById('v39List'); if(!l) return;
    if(!v39B.length){ l.innerHTML='<div style="text-align:center;color:#999;padding:40px 10px;font-weight:700;">अभी कोई सूचना नहीं 📭<br><span style="font-size:11px;">Admin जब भेजेंगे यहाँ दिखेगी</span></div>'; return; }
    l.innerHTML=v39B.map(function(b){
      return '<div class="v39it" onclick="v39View(\''+b._id+'\')"><div class="v39ic" style="background:'+gd(b)+';">'+em(b)+'</div><div style="flex:1;min-width:0;"><b>'+es(b.title||'')+'</b><span>'+es(String(b.msg||'').slice(0,64))+'</span></div>'+(v39Seen[b._id]?'<span style="color:#bbb;font-size:9px;">पढ़ा</span>':'<span style="width:8px;height:8px;border-radius:50%;background:#ff3b3b;flex:0 0 8px;"></span>')+'</div>';
    }).join('');
  }
  function open(){ v39Open(); }
  function markAll(){ v39B.forEach(function(b){ v39Seen[b._id]=1; }); svS(); rd(); v39List(); }
  function closeOv(){ var ov=document.getElementById('v39Ov'); if(ov) ov.classList.remove('open'); }
  function view(id){
    var b=null; v39B.forEach(function(x){ if(x._id===id) b=x; });
    if(!b) return;
    document.getElementById('v39BxH').style.background=gd(b);
    document.getElementById('v39BxE').innerText=em(b);
    document.getElementById('v39BxT').innerText=b.title||'SewaAstra Update';
    document.getElementById('v39BxM').innerText=b.msg||'';
    document.getElementById('v39BxMeta').innerHTML='<span>'+es(VTX[b.type]||'Notice')+'</span><span>🕐 '+es(b.at||'')+'</span>';
    document.getElementById('v39Bx').classList.add('open');
    if(!v39Seen[id]){ v39Seen[id]=1; svS(); rd(); }
  }
  function bxClose(){ document.getElementById('v39Bx').classList.remove('open'); }
  window.v39View=view; window.v39Open=openList; window.v39CloseOv=closeOv; window.v39BxClose=bxClose; window.v39AllRead=markAll;
  /* ─── Chat unread dot (pill) ─── */
  function myUid(){ try{ return firebase.auth().currentUser? firebase.auth().currentUser.uid:''; }catch(e){ return ''; } }
  function myPh(){ try{ return localStorage.getItem('sw_user')||''; }catch(e){ return ''; } }
  function chatOpenNow(){ try{ var m=document.getElementById('chatCallModal'); return m&&m.style.display==='flex'; }catch(e){ return false; } }
  function scan(){
    if(chatOpenNow()){ hidePill(); }
    var uid=myUid(), ph=myPh();
    if(!uid&&!ph) return;
    try{
      var q=SWID.orderQuery(FS,'customer') || (uid? FS.collection('orders').where('uid','==',uid) : FS.collection('orders').where('mobile','==',ph));
      q.get().then(function(s){
        s.docs.forEach(function(d){
          var o=d.data(); var oid=o.id||d.id;
          if(o.status==='Completed'||o.status==='Cancelled') return;
          var key='swc_rd_'+oid, lr=0;
          try{ lr=parseInt(localStorage.getItem(key)||'0',10); }catch(e){}
          if(!lr){ try{ localStorage.setItem(key,String(Date.now())); }catch(e){} return; }
          FS.collection('orders').doc(oid).collection('chats').where('sender','in',['partner','admin']).where('ts','>',lr).get().then(function(cn){
            var n=cn.size||0;
            if(v39U[oid]!==n){ v39U[oid]=n; pill(); }
          }).catch(function(){});
        });
      }).catch(function(){});
    }catch(e){}
  }
  function pill(){
    if(chatOpenNow()){ hidePill(); return; }
    var el=document.getElementById('v39Pill'); if(!el) return;
    var ids=Object.keys(v39U).filter(function(k){ return v39U[k]>0; });
    if(!ids.length){ hidePill(); return; }
    ids.sort(function(a,b2){ return (v39U[b2]||0)-(v39U[a]||0); });
    var n=0; ids.forEach(function(k){ n+=v39U[k]||0; });
    el._oid=ids[0];
    document.getElementById('v39PillT').innerText='💬 '+n+' नया मैसेज — खोलें';
    el.classList.add('open');
  }
  function hidePill(){ var el=document.getElementById('v39Pill'); if(el){ el.classList.remove('open'); } }
  document.addEventListener('click',function(e){ if(e.target&&e.target.closest&&e.target.closest('#v39Pill')){ try{ var oid=document.getElementById('v39Pill')._oid; if(oid&&window.openOrderChat) window.openOrderChat(oid); }catch(x){} } });
  /* mark read on open */
  var _oc39=window.openOrderChat||function(){};
  window.openOrderChat=function(oid){
    try{ if(typeof _oc39==='function') _oc39(oid); }catch(e){}
    try{ localStorage.setItem('swc_rd_'+oid,String(Date.now())); v39U[oid]=0; hidePill(); }catch(e){}
  };
  var _ioc39=window.openInAppChat||function(){};
  window.openInAppChat=function(){
    try{ if(typeof _ioc39==='function') _ioc39(); }catch(e){}
    try{ var a=window.activeChatOrderId; if(a){ localStorage.setItem('swc_rd_'+a,String(Date.now())); v39U[a]=0; hidePill(); } }catch(e){}
  };
  /* ─── START ─── */
  ldS();
  listen();
  setInterval(function(){ try{ scan(); }catch(e){} },8000);
  setTimeout(function(){ try{ scan(); rail(); rd(); }catch(e){} },2500);
  window.addEventListener('load',function(){ setTimeout(function(){ try{ mk(); rail(); }catch(e){} },400); });
  console.log('%c 📢🔔💬 CUSTOMER v3.9 — ADMIN BROADCAST + CHAT DOT ✅ ','background:#15a04a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 21 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([21, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 22 ═══ */
try {
/* ═══════════════ CUSTOMER v4.0 — SUNDER CONFIRM + काम-पूरा 🎉 CELEBRATION + ADMIN EMAIL LOCK ═══════════════ */
(function(){
  if(window.__c40C) return; window.__c40C=1;
  /* ─── CSS ─── */
  var st=document.createElement('style');
  st.innerText=
  '#cCOv{position:fixed;inset:0;z-index:500000;display:none;align-items:center;justify-content:center;background:rgba(15,10,5,.5);backdrop-filter:blur(5px);padding:22px}'+
  '#cCOv.on{display:flex}'+
  '.ccard{width:100%;max-width:400px;border-radius:26px;overflow:hidden;background:#fff;color:#222;box-shadow:0 30px 90px rgba(0,0,0,.45);animation:c40in .28s cubic-bezier(.2,1.25,.4,1)}'+
  'body.dark-mode .ccard{background:#201a14;color:#eee}'+
  '@keyframes c40in{from{transform:scale(.9) translateY(14px);opacity:0}to{transform:none;opacity:1}}'+
  '.cch{background:linear-gradient(135deg,var(--primary,#ff6b00),#ff9a3d);padding:24px 16px 16px;text-align:center;color:#fff}'+
  '.cch .ic{font-size:50px;line-height:1}'+
  '.cch .tt{font-weight:900;font-size:16px;margin-top:8px}'+
  '.ccb{padding:16px 18px 20px}'+
  '.ccmsg{font-size:13px;line-height:1.7;color:#444;font-weight:600;white-space:pre-wrap;word-break:break-word;max-height:38vh;overflow:auto}'+
  'body.dark-mode .ccmsg{color:#cfc6ba}'+
  '.ccb .rwc{display:flex;gap:9px;margin-top:15px}'+
  '.ccb button{flex:1;border:none;border-radius:13px;padding:13px;font-weight:900;font-size:12.5px;cursor:pointer}'+
  '.ccb .no{background:#f2f2f2;color:#666} body.dark-mode .ccb .no{background:#33291f;color:#b8ae9e}'+
  '.ccb .yes{background:linear-gradient(135deg,var(--primary,#ff6b00),#ff9a3d);color:#fff}'+
  '.ccb .yes.danger{background:linear-gradient(135deg,#e53935,#ff6b5a)}'+
  /* celebration */
  '#cCeb{position:fixed;inset:0;z-index:500001;display:none;align-items:center;justify-content:center;padding:20px;background:radial-gradient(circle at 50% 20%,rgba(255,180,40,.35),rgba(20,10,2,.72))}'+
  '#cCeb.on{display:flex}'+
  '.cceb{width:100%;max-width:430px;border-radius:30px;overflow:hidden;box-shadow:0 34px 100px rgba(0,0,0,.5);animation:c40in .34s cubic-bezier(.2,1.3,.4,1)}'+
  '.ccebh{background:linear-gradient(135deg,#0f9d45,#2bc96e);color:#fff;text-align:center;padding:26px 16px 20px;position:relative}'+
  '.ccebh .conf{position:absolute;inset:0;overflow:hidden;pointer-events:none}'+
  '.ccebh .conf i{position:absolute;width:6px;height:6px;border-radius:50%;animation:c40cf 1s ease-out forwards}'+
  '@keyframes c40cf{from{transform:translateY(0) scale(1);opacity:1}to{transform:translateY(-130px) scale(.2);opacity:0}}'+
  '.ring{position:relative;width:104px;height:104px;margin:0 auto 10px}'+
  '.ring span{position:absolute;inset:0;border-radius:50%;border:3px solid transparent;border-top-color:#fff;animation:c40sp 1s linear infinite}'+
  '.ring span:nth-child(2){inset:7px;border-top-color:#ffd700;animation-duration:1.3s;animation-direction:reverse}'+
  '@keyframes c40sp{to{transform:rotate(360deg)}}'+
  '.ring b{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:52px}'+
  '.ccebh .t1{font-size:22px;font-weight:900}'+
  '.ccebh .t2{font-size:11.5px;opacity:.95;font-weight:700;margin-top:4px}'+
  '.ccebb{background:#fff;color:#222;padding:18px 18px 22px}'+
  'body.dark-mode .ccebb{background:#201a14;color:#eee}'+
  '.ccebb .amt{display:flex;justify-content:center;gap:9px;flex-wrap:wrap;margin-bottom:14px}'+
  '.ccebb .amt div{background:#f4f6f8;border-radius:15px;padding:10px 15px;min-width:108px;text-align:center}'+
  'body.dark-mode .ccebb .amt div{background:#2a221a}'+
  '.ccebb .amt b{display:block;font-size:19px;color:var(--primary,#ff6b00)}'+
  '.ccebb .amt span{font-size:9.5px;font-weight:800;color:#999}'+
  '.ccebb .rwc{display:flex;gap:9px}'+
  '.ccebb .rwc button{flex:1;border:none;border-radius:14px;padding:13px;font-weight:900;font-size:12.5px;cursor:pointer}'+
  '.ccebb .ok{background:linear-gradient(135deg,var(--primary,#ff6b00),#ff9a3d);color:#fff}'+
  '.ccebb .rt{background:linear-gradient(135deg,#f5a623,#ffc94d);color:#5a3a00}'+
  '.ccebb .ch{background:#eef1f4;color:#555} body.dark-mode .ccebb .ch{background:#33291f;color:#c0b6a6}'+
  '#cCeb .ct{font-size:12.5px;font-weight:800;color:#444;line-height:1.65;text-align:center}'+
  'body.dark-mode #cCeb .ct{color:#cfc6ba}'+
  '#cCeb .ct b{color:var(--primary,#ff6b00)}';
  document.head.appendChild(st);
  /* ─── CONFIRM ─── */
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function cConfirm(msg,opts){
    opts=opts||{};
    var ov=document.getElementById('cCOv');
    if(!ov){ ov=document.createElement('div'); ov.id='cCOv'; document.body.appendChild(ov); }
    ov.innerHTML='<div class="ccard"><div class="cch"><div class="ic">'+esc(opts.ic||'❓')+'</div><div class="tt">'+esc(opts.title||'पक्का?')+'</div></div><div class="ccb"><div class="ccmsg">'+esc(String(msg==null?'':msg)).replace(/\n/g,'<br>')+'</div><div class="rwc"><button class="no" id="cCNo">✕ '+(opts.no||'नहीं')+'</button><button class="yes '+(opts.danger?'danger':'')+'" id="cCYes">'+(opts.ok||'✅ हाँ')+'</button></div></div></div>';
    ov.classList.add('on');
    return new Promise(function(res){
      document.getElementById('cCYes').onclick=function(){ ov.classList.remove('on'); res(true); };
      document.getElementById('cCNo').onclick=function(){ ov.classList.remove('on'); res(false); };
    });
  }
  window.cConfirm=cConfirm;
  /* ─── CELEBRATION ─── */
  function confetti(){
    var el=document.querySelector('#cCeb .conf'); if(!el) return;
    var colors=['#ffd700','#ff6b00','#fff','#2bc96e','#ff5252'];
    el.innerHTML='';
    for(var i=0;i<18;i++){
      var d=document.createElement('i');
      d.style.left=(10+Math.random()*80)+'%'; d.style.top=(6+Math.random()*30)+'%';
      d.style.background=colors[i%colors.length];
      d.style.animationDelay=(Math.random()*.5)+'s';
      el.appendChild(d);
    }
    setTimeout(function(){ el.innerHTML=''; },1500);
  }
  function cCeleb(o,oid){
    var el=document.getElementById('cCeb');
    if(!el){ el=document.createElement('div'); el.id='cCeb'; document.body.appendChild(el); }
    var items=(o.items||[]).map(function(i){ return (i.n||''); }).join(', ').slice(0,60);
    el.innerHTML='<div class="cceb"><div class="ccebh"><div class="conf"></div><div class="ring"><span></span><span></span><b>✅</b></div><div class="t1">काम पूरा हो गया! 🎉</div><div class="t2">Order '+esc(oid||'')+' • शानदार काम 👏</div></div><div class="ccebb"><div class="amt"><div><b>₹'+(o.total||0).toLocaleString('en-IN')+'</b><span>भुगतान</span></div><div><b>'+(o.mode?esc(o.mode):'—')+'</b><span>माध्यम</span></div></div><div class="ct">🛠️ '+(items?'<b>'+items+'</b>':'-')+'<br>🧑‍🔧 '+(o.partnerName?esc(o.partnerName):'Partner')+(o.partnerPhone?' • +91 '+esc(o.partnerPhone):'')+'</div><div class="rwc" style="margin-top:14px;"><button class="ok" id="cCebOk">ठीक है 👍</button><button class="rt" id="cCebRt" style="display:none;">⭐ रेटिंग दें</button></div></div></div>';
    el.classList.add('on');
    confetti();
    try{ if(navigator.vibrate) navigator.vibrate([80,50,80,50,200]); }catch(e){}
    document.getElementById('cCebOk').onclick=function(){ el.classList.remove('on'); };
    var rt=document.getElementById('cCebRt');
    if(typeof window.openRateModal==='function'){
      rt.style.display='';
      rt.onclick=function(){ el.classList.remove('on'); try{ window.openRateModal(oid); }catch(e){} };
    }
  }
  window.cCeleb=cCeleb;
  /* ─── WATCHER: sirf LIVE transition to Completed ─── */
  function watch(){
    if(window.__c40W) return; window.__c40W=1;
    var prev={}, fired={};
    try{
      if(typeof window.myOrdersQuery!=='function') return;
      myOrdersQuery().onSnapshot(function(snap){
        snap.docChanges().forEach(function(ch){
          var d=ch.doc, o=d.data(), oid=o.id||d.id;
          var p=prev[oid];
          prev[oid]=o.status;
          if(o.status==='Completed'&&p&&p!=='Completed'&&!fired[oid]&&ch.type==='modified'){ fired[oid]=1; cCeleb(o,oid); }
        });
      },function(){});
    }catch(e){}
  }
  var tw=0;
  function tryW(){
    try{
      if(window.firebase&&firebase.auth().currentUser&&typeof window.myOrdersQuery==='function'){ clearInterval(tw); setTimeout(watch,1200); }
    }catch(e){}
  }
  tw=setInterval(tryW,800);
  /* ─── ADMIN LOCK resync (real Firebase email) ─── */
  try{
    firebase.auth().onAuthStateChanged(function(u){
      var em=(u&&u.email)?u.email:'';
      if(window.checkAdminAccess) window.checkAdminAccess(em);
    });
  }catch(e){}
  console.log('%c 🎉🔔🔐 CUSTOMER v4.0 — SUNDER + CELEBRATION + ADMIN EMAIL LOCK ✅ ','background:#15a04a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 22 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([22, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 23 ═══ */
try {
/* ═══════════════ CUSTOMER v4.0B — सारे confirm → SUNDER box ═══════════════ */
(function(){
  if(window.__c40B) return; window.__c40B=1;

  window.cancelMyOrder = function(oid){
    window.cConfirm('ऑर्डर '+oid+' रद्द करना है?',{ic:'❌',title:'Order Cancel',ok:'हाँ, रद्द करें'}).then(function(ok){
      if(!ok) return;
      FS.collection('orders').doc(oid).update({ status:'Cancelled' })
        .then(function(){
          showToast('❌ ऑर्डर रद्द हो गया');
          try{ closeCustomAlert(); }catch(e){}
          setTimeout(function(){ try{ window.showHistory(); }catch(e){} },400);
        })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    });
  };

  window.deleteMyOrder = function(oid){
    window.cConfirm('ऑर्डर '+oid+' को history से हमेशा के लिए delete करना है?',{ic:'🗑️',title:'Delete Order',ok:'हाँ, delete करें',danger:true}).then(function(ok){
      if(!ok) return;
      FS.collection('orders').doc(oid).delete()
        .then(function(){
          showToast('🗑️ ऑर्डर delete हो गया');
          try{ closeCustomAlert(); }catch(e){}
          setTimeout(function(){ try{ window.showHistory(); }catch(e){} },350);
        })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    });
  };

  window.clearMyHistory = function(){
    window.cConfirm('सभी पूर्ण/रद्द ऑर्डर history से delete हो जाएंगे। पक्का?',{ic:'🧹',title:'History साफ़ करें',ok:'हाँ, सब delete करें',danger:true}).then(function(ok){
      if(!ok) return;
      showLoader('History साफ़ हो रही है...');
      myOrdersQuery().get().then(function(snap){
        var batch=FS.batch(); var n=0;
        snap.docs.forEach(function(d){
          var s=d.data().status;
          if(s==='Completed'||s==='Cancelled'){ batch.delete(d.ref); n++; }
        });
        return batch.commit().then(function(){ return n; });
      }).then(function(n){
        hideLoader();
        try{ closeCustomAlert(); }catch(e){}
        showToast(n?('🗑️ '+n+' ऑर्डर delete हो गए'):'कोई पूर्ण/रद्द ऑर्डर नहीं मिला');
        setTimeout(function(){ try{ window.showHistory(); }catch(e){} },400);
      }).catch(function(e){ hideLoader(); showAlert('त्रुटि', e.message); });
    });
  };

  window.adminDeleteOrder = function(oid){
    window.cConfirm('ऑर्डर '+oid+' को हमेशा के लिए delete करना है?\n(Chat history भी हट जाएगी)',{ic:'🗑️',title:'Delete Order',ok:'हाँ, delete करें',danger:true}).then(function(ok){
      if(!ok) return;
      FS.collection('orders').doc(oid).delete()
        .then(function(){ showToast('🗑️ ऑर्डर '+oid+' delete हो गया'); })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    });
  };

  window.adminVerifyPayment = function(oid, ref){
    window.cConfirm('PhonePe Business app me check kiya?\nUTR: '+(ref||'—')+'\n\nPayment VERIFY karein?',{ic:'💜',title:'UTR Verify',ok:'✅ VERIFY करें'}).then(function(ok){
      if(!ok) return;
      FS.collection('orders').doc(oid).update({
        'payment.verified':true,
        'payment.status':'PAID (Admin Verified)',
        'payment.verifiedAt':Date.now()
      }).then(function(){ showToast('✅ Payment verified — '+oid); })
        .catch(function(e){ showAlert('त्रुटि', e.message); });
    });
  };

  /* customer-side admin: category delete */
  window.deleteAdminCategory = function(key){
    window.cConfirm("क्या आप वाकई कैटेगरी '"+key+"' और उसके अंतर्गत सभी सर्विसेज को हटाना चाहते हैं?",{ic:'🗑️',title:'Category Delete',ok:'हाँ, हटाएँ',danger:true}).then(function(ok){
      if(!ok) return;
      try{ categoriesData = categoriesData.filter(function(c){ return c.key!==key; }); }catch(e){}
      try{ delete mainData[key]; }catch(e){}
      try{ localStorage.setItem('sw_custom_categories', JSON.stringify(categoriesData)); }catch(e){}
      try{ localStorage.setItem('sw_custom_services', JSON.stringify(mainData)); }catch(e){}
      try{ renderCategoriesGrid(); }catch(e){}
      try{ populateAdminCatDropdown(); }catch(e){}
      try{ renderAdminCategoriesList(); }catch(e){}
      showToast('कैटेगरी सफलतापूर्वक हटा दी गई!');
    });
  };
  console.log('%c 🔔 CUSTOMER v4.0B — ALL CONFIRMS SUNDER ✅ ','background:#1976d2;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 23 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([23, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 24 ═══ */
try {
/* सभी native alert() → SUNDER (Customer) */
(function(){
  if(window.__c40A) return; window.__c40A=1;
  window.alert=function(m){
    try{ if(typeof showAlert==='function'){ showAlert('सूचना', String(m==null?'':m).replace(/\n/g,'<br>')); return; } }catch(e){}
  };
  console.log('%c 🔔 CUSTOMER v4.0C — ALERT SUNDER ✅ ','background:#ff6b00;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 24 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([24, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 25 ═══ */
try {
/* ═══════════════ CUSTOMER v4.2 — URBAN-STYLE ITEM DETAIL (photo + rate + qty + add) ═══════════════ */
(function(){
  if(window.__c42C) return; window.__c42C=1;
  var ST=document.createElement('style');
  ST.innerText=
  '#cIM{position:fixed;inset:0;z-index:260000;display:none;align-items:flex-end;justify-content:center;background:rgba(10,6,2,.62);backdrop-filter:blur(5px)}'+
  '#cIM.on{display:flex}'+
  '.cimsh{width:100%;max-width:540px;max-height:92vh;background:#fff;color:#222;border-radius:26px 26px 0 0;overflow:hidden;display:flex;flex-direction:column;animation:cimUp .3s cubic-bezier(.2,.9,.3,1)}'+
  'body.dark-mode .cimsh{background:#1e1a16;color:#eee}'+
  '@keyframes cimUp{from{transform:translateY(70%)}to{transform:none}}'+
  '.cimimg{width:100%;height:210px;object-fit:cover;background:#eee;position:relative}'+
  '.cimx{position:absolute;top:12px;right:12px;width:34px;height:34px;border-radius:50%;background:rgba(0,0,0,.45);border:none;color:#fff;font-size:17px;cursor:pointer;backdrop-filter:blur(4px)}'+
  '.cimb{padding:16px 18px 24px;overflow-y:auto}'+
  '.cimh{font-size:20px;font-weight:900;margin:0}'+
  '.cimsub{font-size:11px;color:#999;font-weight:700;margin:3px 0 0}'+
  '.cimrt{display:inline-block;margin-top:10px;background:#fff3e6;color:#b45300;border:1px solid #ffd9b3;border-radius:20px;padding:5px 13px;font-weight:900;font-size:13px}'+
  '.cimopt{margin-top:14px}'+
  '.cimopt .lb{font-size:12px;font-weight:900;margin-bottom:7px}'+
  '.optt{display:flex;flex-wrap:wrap;gap:7px}'+
  '.optt label{border:1.6px solid #e5ded6;border-radius:12px;padding:8px 11px;font-size:11.5px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:5px}'+
  'body.dark-mode .optt label{border-color:#3a3128;color:#d9cfc2}'+
  '.optt input{accent-color:var(--primary,#ff6b00)}'+
  '.optt label.on{border-color:var(--primary,#ff6b00);background:#fff3e6;color:#b45300}'+
  'body.dark-mode .optt label.on{background:#3a2a16;color:#ffc08a}'+
  '.cimqty{display:flex;align-items:center;gap:16px;margin-top:16px}'+
  '.cimqty .lb{font-size:12px;font-weight:900}'+
  '.stp{display:flex;align-items:center;gap:0;border:1.6px solid #ddd;border-radius:30px;overflow:hidden}'+
  '.stp button{width:42px;height:42px;border:none;background:#f6f3ef;font-size:19px;font-weight:900;cursor:pointer}'+
  'body.dark-mode .stp button{background:#2c241d;color:#eee}'+
  '.stp b{min-width:44px;text-align:center;font-size:16px}'+
  '.cimadd{margin-top:14px;width:100%;border:none;border-radius:16px;padding:15px;background:linear-gradient(135deg,var(--primary,#ff6b00),#ff9a3d);color:#fff;font-weight:900;font-size:14px;cursor:pointer}'+
  '.cimnote{font-size:10px;color:#999;font-weight:700;text-align:center;margin-top:9px;line-height:1.5}';
  document.head.appendChild(ST);

  var ov=null;
  function ovr(){
    if(ov) return ov;
    ov=document.createElement('div'); ov.id='cIM';
    ov.onclick=function(e){ if(e.target===ov) cImClose(); };
    document.body.appendChild(ov);
    return ov;
  }
  function fmtN(v){ return '₹'+Number(v||0).toLocaleString('en-IN'); }
  window.cImClose=function(){ var o=document.getElementById('cIM'); if(o) o.classList.remove('on'); };

  window.cShow=function(cat,idx){
    try{
      var svc=(mainData[cat]||[])[idx]; if(!svc) return;
      var opts=svc.subOptions||[];
      ovr();
      ov.innerHTML='<div class="cimsh"><div style="position:relative;"><img class="cimimg" src="'+svc.i+'" onerror="this.src=\'https://cdn-icons-png.flaticon.com/512/1046/1046784.png\'"><button class="cimx" onclick="cImClose()">✕</button></div>'+
        '<div class="cimb">'+
          '<h3 class="cimh">'+svc.n+'</h3>'+
          '<div class="cimsub">⭐ 4.8 • 320+ सेवाएँ • '+catNameOf(cat)+'</div>'+
          '<div><span class="cimrt" id="cimRate">'+fmtN(svc.p)+' से शुरू</span></div>'+
          '<div class="cimopt" '+(opts.length?'':'style="display:none"')+'><div class="lb">विकल्प चुनें (मेहनत/material जोड़ें):</div><div class="optt" id="cimOpts">'+
          opts.map(function(o,i){
            return '<label '+(i===0?'class="on"':'')+'><input type="radio" name="cimO" '+(i===0?'checked':'')+' onchange="cImPick('+i+',\''+escName(cat)+'\','+idx+')"> '+o+'</label>';
          }).join('')+'</div></div>'+
          '<div class="cimqty"><span class="lb">कितने?</span><div class="stp"><button onclick="cImQ(-1)">−</button><b id="cimQ">1</b><button onclick="cImQ(1)">+</button></div></div>'+
          '<button class="cimadd" id="cimAddB">🛒 ADD — '+(opts.length?fmtN(svc.p+extraOf(opts[0])):fmtN(svc.p))+'</button>'+
          '<div class="cimnote">🧑‍🔧 Partner घर visit करेगा • Visit fee + सामान का rate bill में साफ़ लिखा मिलेगा</div>'+
        '</div></div>';
      ov.classList.add('on');
      window.__cim={cat:cat,idx:idx,svc:svc,q:1,opt:0};
    }catch(e){}
  };
  function catNameOf(k){ try{ var c=categoriesData.find(function(x){return x.key===k;}); return c?c.name:k; }catch(e){ return k; } }
  function escName(k){ return String(k).replace(/['"\\]/g,''); }
  function extraOf(o){ var m=String(o||'').match(/\+₹(\d+)/); return m?parseInt(m[1],10):0; }
  function priceNow(){
    var s=window.__cim; if(!s) return 0;
    var o=(s.svc.subOptions||[])[s.opt]||'';
    return (Number(s.svc.p)||0)+extraOf(o);
  }
  window.cImPick=function(i,cat,idx){ try{ window.__cim.opt=i; document.querySelectorAll('#cIM .optt label').forEach(function(l,x){ l.classList.toggle('on',x===i); }); cImSync(); }catch(e){} };
  window.cImQ=function(d){ try{ window.__cim.q=Math.max(1,(window.__cim.q||1)+d); cImSync(); }catch(e){} };
  function cImSync(){
    var s=window.__cim; if(!s) return;
    document.getElementById('cimQ').innerText=s.q;
    var el=document.getElementById('cimAddB');
    if(el) el.innerText='🛒 ADD ×'+s.q+' — '+fmtN(priceNow()*s.q);
  }
  /* ADD → cart (qty×) */
  window.cImAddQty=function(){
    var s=window.__cim; if(!s) return;
    var n=s.svc.n, p=priceNow();
    var o=(s.svc.subOptions||[])[s.opt]||'';
    for(var i=0;i<(s.q||1);i++){
      var ex=(function(){ var c=cart.find(function(x){ return x.n===n && (x.selectedSub||'')===(o||''); }); if(c){ c.qty=(c.qty||1)+1; } else cart.push({n:n,p:p,selectedSub:o,qty:1,cat:s.cat,catName:catNameOf(s.cat)}); })();
    }
    try{ var tc=cart.reduce(function(a,c){return a+(c.qty||1);},0); document.getElementById('bCount').innerText=tc; }catch(e){}
    try{ showToast((s.svc.n)+' ×'+s.q+' कार्ट में जोड़ दिया! 🛒'); }catch(e){}
    try{ if(typeof renderCart==='function') renderCart(); }catch(e){}
    try{ if(typeof closeCart==='function'){} }catch(e){}
    cImClose();
  };
  /* override createCard so image/naam modal खोलें + ADD button नया flow */
  try{
    var _cc=window.createCard;
    window.createCard=function(item, uniqueId){
      var pos=String(uniqueId).lastIndexOf('_'), cat=pos>0?String(uniqueId).slice(0,pos):'general';
      var subOptionsHtml='';
      if(item.subOptions && item.subOptions.length>0){
        subOptionsHtml='<div class="service-sub-options" id="subOpt_'+uniqueId+'" style="display:flex;">'+
          '<div style="font-size:11px;font-weight:bold;color:var(--primary);margin-bottom:4px;">विकल्प चुनें (Select Option):</div>';
        item.subOptions.forEach(function(opt,idx){
          var checkedAttr=(idx===0)?'checked':'';
          subOptionsHtml+='<label><input type="radio" name="sub_'+uniqueId+'" value="'+opt+'" '+checkedAttr+' onchange="updateCardPrice(\''+uniqueId+'\', '+item.p+')"> '+opt+'</label>';
        });
        subOptionsHtml+='</div>';
      }
      return '<div class="card" style="cursor:pointer;">'+
        '<div class="card-top">'+
          '<img loading="lazy" decoding="async" src="'+item.i+'" style="cursor:pointer;" onclick="cShow(\''+cat+'\','+String(uniqueId).slice(pos+1)+')" onerror="this.src=\'https://cdn-icons-png.flaticon.com/512/1046/1046784.png\'" />'+
          '<div class="card-info">'+
            '<h4 onclick="cShow(\''+cat+'\','+String(uniqueId).slice(pos+1)+')">'+item.n+'</h4>'+
            '<div class="rating-row"><i class="fa fa-star"></i><span class="rating-val">4.8</span><span class="review-count">(320+ reviews)</span></div>'+
            '<div class="price-row"><b id="priceDisplay_'+uniqueId+'">₹'+item.p+'</b>'+
            '<button class="add-btn" id="btn_'+uniqueId+'" onclick="addToCart(\''+item.n+'\', '+item.p+', \''+uniqueId+'\')">ADD</button></div>'+
          '</div></div>'+
        subOptionsHtml+'</div>';
    };
  }catch(e){}
  window.cImAddQty2=window.cImAddQty;
  /* ADD button in modal attaches once */
  function bindModalAdd(){
    var b=document.getElementById('cimAddB');
    if(b && !b._c42){ b._c42=1; b.onclick=window.cImAddQty; }
    setTimeout(bindModalAdd,500);
  }
  bindModalAdd();
  console.log('%c 🛒 CUSTOMER v4.2 — ITEM PHOTO+RATE+QTY MODAL ✅ ','background:#ff6b00;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 25 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([25, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 26 ═══ */
try {
/* ═══════════════ CUSTOMER v4.3 — PARTNER VISIT MOVING POPUP + WORK-EDIT OTP ═══════════════ */
(function(){
  if(window.__c43) return; window.__c43=1;
  var ST=document.createElement('style');
  ST.innerText=
  '#v43Vis{position:fixed;right:10px;bottom:118px;z-index:280000;display:none;flex-direction:column;gap:7px;width:150px}'+
  '#v43Vis.on{display:flex}'+
  '.v43pill{position:relative;border-radius:20px;padding:10px 12px;color:#fff;font-weight:900;font-size:11px;line-height:1.35;cursor:pointer;box-shadow:0 12px 30px rgba(13,71,161,.4);overflow:hidden;background:linear-gradient(135deg,#0d47a1,#1e88e5);animation:v43mv 1.6s ease-in-out infinite;text-align:left}'+
  '.v43pill.green{background:linear-gradient(135deg,#0f9d45,#2bc96e);animation-delay:.15s;box-shadow:0 12px 30px rgba(15,157,69,.4)}'+
  '.v43pill.org{background:linear-gradient(135deg,#e65100,#ff9800);animation-delay:.3s;box-shadow:0 12px 30px rgba(230,81,0,.4)}'+
  '@keyframes v43mv{0%,100%{transform:translateY(0) translateX(0)}25%{transform:translateY(-5px) translateX(2px)}50%{transform:translateY(-9px) translateX(0)}75%{transform:translateY(-5px) translateX(-2px)}}'+
  '.v43dot{width:9px;height:9px;border-radius:50%;background:#ffd60a;display:inline-block;margin-right:5px;animation:v43blink 1s infinite}'+
  '@keyframes v43blink{0%,100%{opacity:1}50%{opacity:.2}}'+
  '.v43close{position:absolute;top:3px;right:7px;color:rgba(255,255,255,.85);font-size:13px;cursor:pointer;z-index:3}'+
  '.v43pill b{display:block;font-size:11.5px;text-shadow:0 1px 2px rgba(0,0,0,.3)}'+
  '.v43pill span{font-size:9px;opacity:.95;font-weight:800}'+
  '.v43act{display:flex;gap:6px}'+
  '.v43act button{flex:1;border:none;border-radius:13px;padding:9px 4px;font-weight:900;font-size:10px;cursor:pointer}'+
  '.v43act .t{background:#fff;color:#0d47a1}'+
  '.v43act .c{background:rgba(255,255,255,.25);color:#fff}'+
  /* edit OTP bar (left, niche) */
  '#wUOtpBar{position:fixed;bottom:150px;left:14px;z-index:8000;max-width:66vw;background:linear-gradient(135deg,#3a1c0a,#1a1030);color:#fff;border:1.5px solid #ff9a3d;border-radius:18px;padding:9px 13px;font-size:10.5px;font-weight:800;box-shadow:0 10px 26px rgba(0,0,0,.45);line-height:1.55}'+
  '#wUOtpBar b{color:#ffd700;font-size:15px;letter-spacing:2px;margin-left:4px}'+
  '#wUOtpBar .x{float:right;color:rgba(255,255,255,.6);margin-left:8px;cursor:pointer;font-size:12px}';
  document.head.appendChild(ST);

  var act={};  /* oid -> status/ts */
  var hid=null;
  function esc3(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }

  /* 1) moving visit pill */
  function paintVis(o){
    var w=document.getElementById('v43Vis');
    if(!o){ if(w) w.classList.remove('on'); return; }
    if(hid===o.id){ if(w) w.classList.remove('on'); return; }
    if(!w){ w=document.createElement('div'); w.id='v43Vis'; document.body.appendChild(w); }
    var st=o.status, pn=o.partnerName||'Partner';
    var icon='🧑‍🔧', line, cls='';
    if(st==='Accepted'){ icon='🧑‍🔧'; line='Partner आपके लिए visit पर आ रहा है'; }
    else if(st==='On the Way'){ icon='🛵'; line='Partner आपके घर के रास्ते में है — visit'; cls='green'; }
    else { icon='🔧'; line='Partner आपके घर काम कर रहा है'; cls='org'; }
    var total=o.items?o.items.length:0;
    w.className=''; void w.offsetWidth; w.classList.add('on');
    w.innerHTML=
      '<div class="v43pill '+cls+'" onclick="c43Go(\''+esc3(o.id)+'\')"><span class="v43close" onclick="event.stopPropagation();c43Hide()">✕</span>'+
        '<span class="v43dot"></span>'+icon+' <b>'+esc3(pn)+'</b>'+
        '<span>'+esc3(line)+' • '+(st==='Working'?'काम चालू':'Visit')+'</span></div>'+
      '<div class="v43act">'+
        '<button class="t" onclick="c43Track(\''+esc3(o.id)+'\')">🗺️ Track</button>'+
        '<button class="c" onclick="c43Chat(\''+esc3(o.id)+'\')">💬 Chat</button>'+
      '</div>';
  }
  window.c43Hide=function(){ var w=document.getElementById('v43Vis'); if(w) w.classList.remove('on'); };
  window.c43Go=function(oid){ try{ if(window.openLiveTracking) window.openLiveTracking(oid); }catch(e){ c43Track(oid); } };
  window.c43Track=function(oid){ try{ if(window.openLiveTracking) window.openLiveTracking(oid); }catch(e){} };
  window.c43Chat=function(oid){ try{ if(window.openOrderChat) window.openOrderChat(oid); }catch(e){} };

  function watcher(){
    try{
      if(typeof window.myOrdersQuery!=='function') return;
      if(window.__c43Sub) return;
      window.__c43Sub=myOrdersQuery().onSnapshot(function(snap){
        act={};
        var latest=null;
        snap.docs.forEach(function(d){
          var o=d.data(); var oid=o.id||d.id;
          if(['Accepted','On the Way','Working'].indexOf(o.status)>-1){
            act[oid]=o.status;
            if(!latest || (o.createdAt||0)>(latest.createdAt||0)) latest=o;
          }
        });
        if(latest) hid=null;   /* naya active → phir dikhao */
        paintVis(latest);
      },function(){});
    }catch(e){}
  }

  /* 2) Work-EDIT OTP display */
  function editWatch(){
    try{
      if(!window.myOrdersQuery) return;
      if(window.__c43EditSub) return;
      window.__c43EditSub=myOrdersQuery().onSnapshot(function(snap){
        var ew=null;
        snap.docs.forEach(function(d){
          var o=d.data(); var oid=o.id||d.id;
          if(o.wUOtp && ['Accepted','On the Way','Working'].indexOf(o.status)>-1){
            if(!ew || (o.createdAt||0)>(ew.createdAt||0)) ew=o;
          }
        });
        var el=document.getElementById('wUOtpBar');
        if(!ew){ if(el) el.remove(); return; }
        if(!el){ el=document.createElement('div'); el.id='wUOtpBar'; el.style.cssText=''; document.body.appendChild(el); }
        el.innerHTML='<span class="x" onclick="this.parentNode.remove()">✕</span>✏️ Partner काम बढ़ाना/बदलना चाहता है — नया OTP: <b>'+esc3(ew.wUOtp)+'</b><br><span style="font-size:9px;opacity:.85;">यह OTP partner को बताएँ — वही आपके order में update करेगा</span>';
      },function(){});
    }catch(e){}
  }

  setTimeout(function(){ watcher(); editWatch(); },900);
  setTimeout(function(){ try{ watcher(); editWatch(); }catch(e){} },6000);
  console.log('%c 🧑‍🔧 CUSTOMER v4.3 — VISIT POPUP + EDIT OTP ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 26 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([26, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 27 ═══ */
try {
/* ═══════════════ CUSTOMER v4.4 — LIVE WALLET(SW ₹) + COINS + REFER ₹1000-COIN + SERVICE RATING + EDIT-POPUP ═══════════════ */
(function(){
  if(window.__c44) return; window.__c44=1;

  function wEsc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function wKey(){
    try{
      var st=(localStorage.getItem('sw_user')||'').trim();
      if(/^\d{10}$/.test(st)) return st;
      if(st.indexOf('@')>-1) return st;
      var u=firebase.auth().currentUser; if(u) return u.uid;
      if(st) return st;
    }catch(e){}
    return '';
  }
  function wAuthed(){ try{ return !!firebase.auth().currentUser || localStorage.getItem('sw_logged')==='true'; }catch(e){ return false; } }
  var wC={sw:0,coins:0,refBy:'',refKind:'',refPaid:0,led:[]};
  var wRef=null;
  function wMy(){ wRef=FS.collection('users').doc(wKey()); return wRef; }

  /* ─── ensure wallet doc ─── */
  function wEnsure(){
    var k=wKey(); if(!k) return;
    try{
      FS.collection('users').doc(k).get().then(function(d){
        var upd={};
        if(!d.exists){ upd={key:k,kind:'customer',swBal:0,coins:0,refPaid:0,led:[],createdAt:new Date().toLocaleString('en-IN'),ts:Date.now()}; }
        else{
          var x=d.data();
          if(typeof x.swBal!=='number') upd.swBal=0;
          if(typeof x.coins!=='number') upd.coins=0;
          if(typeof x.refPaid!=='number') upd.refPaid=0;
          if(!x.led) upd.led=[];
        }
        if(Object.keys(upd).length) FS.collection('users').doc(k).set(upd,{merge:true}).catch(function(){});
        var uu2=''; try{ uu2=firebase.auth().currentUser?firebase.auth().currentUser.uid:''; }catch(e){}
        if(uu2) FS.collection('users').doc(k).set({uid:uu2},{merge:true}).catch(function(){});
        FS.collection('users').doc(k).onSnapshot(function(s){ if(s.exists) wC=Object.assign(wC,s.data()); },function(){});
      }).catch(function(){});
    }catch(e){}
  }
  function boot44(){ if(window.__c44Boot) return; window.__c44Boot=1; setTimeout(function(){ try{ wEnsure(); wSubRate(); wWatch(); }catch(e){} },1400); }
  try{ if(firebase.auth&&firebase.auth().currentUser) boot44(); }catch(e){}
  firebase.auth().onAuthStateChanged(function(u){ if(u) boot44(); });
  window.addEventListener('load',function(){ if(localStorage.getItem('sw_logged')==='true') setTimeout(boot44,2200); });

  /* ═══ 1) SERVICE RATING — हर service पर real rating (service_ratings collection) ═══ */
  var rAgg={}; /* 'cat|name' -> {sum,count} */
  function wSubRate(){
    try{
      /* SCALE: service_ratings (हर rating की row — अनबाउंड) की जगह ab svc_stats
         (हर service का 1 aggregate doc — bounded, chhota) subscribe होता है */
      FS.collection('svc_stats').limit(200).onSnapshot(function(s){
        var a={};
        s.docs.forEach(function(d){ var x=d.data(); var k=String(x.cat||'')+'|'+String(x.sn||''); if(!a[k]) a[k]={sum:0,count:0}; a[k].sum+=Number(x.sum)||0; a[k].count+=Number(x.count)||0; });
        window.__rAgg=a; rAgg=a;
        try{ reBadge(); }catch(e){}
      },function(){});
      /* पुराने ratings (svc_stats बनने से पहले) — एक बार सीमित backfill */
      try{
        FS.collection('svc_stats').limit(200).get().then(function(st){
          if(st.empty){
            return FS.collection('service_ratings').limit(400).get().then(function(rs){
              var a2={};
              rs.docs.forEach(function(d){ var x=d.data(); var k=String(x.cat||'')+'|'+String(x.sn||''); if(!a2[k]) a2[k]={sum:0,count:0}; a2[k].sum+=Number(x.stars)||0; a2[k].count++; });
              rAgg=a2; try{ reBadge(); }catch(e){}
            }).catch(function(){});
          }
        }).catch(function(){});
      }catch(e){}
    }catch(e){}
  }
  function reBadge(){ try{ window.dispatchEvent(new Event('sewaastra-rebadge')); }catch(e){} }
  function cRateGet(cat,nm){ try{ return rAgg[String(cat||'')+'|'+String(nm||'')]||null; }catch(e){ return null; } }
  function cRateLine(cat,nm){
    var r=cRateGet(cat,nm);
    if(r&&r.count) return '<span class="rating-val" style="color:#f5a623;">'+Math.round(r.sum/r.count*10)/10+'</span><span class="review-count"> ('+(r.count===1?'1 रेटिंग':r.count+' रेटिंग')+')</span>';
    return '<span class="rating-val" style="color:#aaa;">नया</span><span class="review-count"> (पहली रेटिंग का इंतज़ार)</span>';
  }
  /* createCard wrap — rating row live */
  try{
    var _cCard=window.createCard;
    if(typeof _cCard==='function'){
      window.createCard=function(item,uid){
        var html=_cCard(item,uid);
        try{
          var cat=(String(uid||'').split('_')[0])||'general', nm=item&&item.n||'';
          var okCat=!!(window.categoriesData||[]).find(function(c){return c.key===cat;});
          if(!okCat){ for(var kk in window.mainData){ if(window.mainData[kk]&&window.mainData[kk].some(function(s){return s&&s.n===nm;})){ cat=kk; break; } } }
          html=html.replace(/<span class="rating-val">[\s\S]*?<\/span>\s*<span class="review-count">[\s\S]*?<\/span>/, cRateLine(cat,nm));
        }catch(e){}
        return html;
      };
    }
  }catch(e){}

  /* ═══ 2) submitProRating — order के हर service/item में rating save + service_ratings ═══ */
  var _cRate=window.submitProRating;
  window.submitProRating=function(oid){
    try{ if(typeof _cRate==='function') _cRate(oid); }catch(e){}
    try{ wRateSvc(oid); }catch(e){}
  };
  function wRateSvc(oid){
    var stars=Number(window.currentRating)||5;
    FS.collection('orders').doc(oid).get().then(function(d){
      if(!d.exists) return;
      var o=d.data(); if(!o||!o.items) return;
      var items=(o.items||[]).map(function(i){ return {n:i.n,p:i.p,qty:i.qty||1,cat:i.cat||'',catName:i.catName||'',r:{stars:stars,at:new Date().toLocaleString('en-IN')}}; });
      FS.collection('orders').doc(oid).update({items:items}).catch(function(){});
      items.forEach(function(i){
        /* 🔒 by में कभी फोन नहीं — यह collection बिना login के भी पढ़ी जा सकती है.
     पहले localStorage('sw_user') यानी फोन नंबर जाता था. */
      /* 🔒 पहले .add() था — हर बार नई random ID, यानी एक ही order पर बटन
         दबाते रहो और rating बढ़ती जाए (svc_stats हर बार increment होता है).
         अब ID fields से तय होती है, इसलिए दूसरी बार वही ID बनेगी और rules
         उसे create नहीं करने देंगी: एक order = एक rating प्रति service.
         '/' हटाना ज़रूरी है, वरना doc ID का रास्ता टूट जाता है — rules भी
         यही शर्त लगाती हैं. */
      (function(){
        var rCat=String(i.cat||'').replace(/\//g,'_').slice(0,40);
        var rSn =String(i.n||'').replace(/\//g,'_').slice(0,80);
        var rid = String(oid)+'__'+rCat+'__'+rSn;
        FS.collection('service_ratings').doc(rid).set({
          cat:rCat, catName:i.catName||'', sn:rSn, stars:stars, orderId:oid,
          by:(getUID()||'anon'), ts:Date.now(), at:new Date().toLocaleString('en-IN')
        }).catch(function(){});
      })();
        try{
          var key=String(i.cat||'')+'__'+String(i.n||'').replace(/[^A-Za-z0-9]/g,'_');
          /* 🔒 counters अब server trigger से बढ़ते हैं (rating हैक बंद) */ void ({cat:i.cat||'',catName:i.catName||'',sn:i.n||'',sum:firebase.firestore.FieldValue.increment(stars),count:firebase.firestore.FieldValue.increment(1),lastAt:Date.now()},{merge:true}).catch(function(){});
        }catch(e){}
      });
    }).catch(function(){});
  };

  /* ═══ 3) LAYOUT — category tile photo/emoji support (#4 की customer side) ═══ */
  function isEmoji(s){ return /[^\u0000-\u007F]/.test(String(s||'')); }
  function iconHTML(cat,small){
    if(cat.img) return '<img src="'+wEsc(cat.img)+'" onerror="this.onerror=null;this.style.display=\'none\'" style="width:100%;height:100%;object-fit:cover;border-radius:'+(small?'10px':'14px')+';position:absolute;inset:0;">';
    var ic=String(cat.icon||'');
    if(isEmoji(ic)) return '<span style="font-size:'+(small?'20px':'26px')+';line-height:1;">'+ic+'</span>';
    return '<i class="fa '+(/^fa-/.test(ic)?ic:('fa-'+ic))+'"></i>';
  }
  function patchTiles(){
    try{
      var grid=document.getElementById('catGridArea');
      if(grid){
        var vis=(window.categoriesData||[]).slice(0,7);
        var els=grid.querySelectorAll('.cat-item');
        for(var i=0;i<vis.length&&i<els.length;i++){
          var c=els[i].querySelector('.cat-icon');
          if(c) c.innerHTML=iconHTML(vis[i],false);
        }
      }
      var mg=document.getElementById('moreCategoriesGridArea');
      if(mg){
        var cats2=(window.categoriesData||[]), e2=mg.querySelectorAll('.cat-item');
        for(var j=0;j<cats2.length&&j<e2.length;j++){ var c2=e2[j].querySelector('.cat-icon'); if(c2) c2.innerHTML=iconHTML(cats2[j],true); }
      }
    }catch(e){}
  }
  try{
    var _cg=window.renderCategoriesGrid; if(typeof _cg==='function') window.renderCategoriesGrid=function(){ _cg(); setTimeout(patchTiles,30); };
    var _mg=window.renderMoreCategoriesGrid; if(typeof _mg==='function') window.renderMoreCategoriesGrid=function(){ _mg(); setTimeout(patchTiles,30); };
    window.addEventListener('sewaastra-rebadge',function(){ setTimeout(patchTiles,30); });
  }catch(e){}
  /* cat icon override to emoji/image + fa-fallback in original markup — patch old markup too */
  try{
    var _load=window.load;
    if(typeof _load==='function') window.load=function(k){ _load(k); setTimeout(function(){ patchTiles(); },40); };
  }catch(e){}

  /* ═══ 4) WALLET UI (custReqAction 'Wallet'/'Referral') ═══ */
  function ledRow(x){
    var sign=(x.amt||0)>=0?'+':'−';
    var icon=(x.k==='coin')?'🪙':(x.amt<0?'💸':'💰');
    return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-bottom:1px dashed #eee;font-size:12px;">'+
      '<div><span style="font-weight:700;">'+icon+' '+(x.note||'')+'</span><br><span style="font-size:9.5px;color:#999;">'+(x.at||'')+'</span></div>'+
      '<b style="color:'+((x.amt||0)>=0?'#15a04a':'#e53935')+';">'+sign+' '+(x.k==='coin'?Math.abs(x.amt||0)+' coin':'₹'+Math.abs(x.amt||0))+'</b></div>';
  }
  window.c44Wallet=function(tab){
    if(!wKey()) return showAlert('लॉगिन करें','Wallet देखने के लिए पहले अपने नंबर से लॉगिन करें।');
    var phone=wKey();
    FS.collection('users').doc(phone).get().then(function(d){
      var u=d.exists?d.data():{swBal:0,coins:0,refBy:'',refKind:'',refPaid:0,led:[]};
      wC=Object.assign(wC,u);
      var led=(u.led||[]).slice(-18).reverse();
      var nextM=[100,100,150,150,500], paid=(u.refPaid||0), prog=nextM.slice(0,paid).reduce(function(a,b){return a+b;},0);
      var code=/^\d{10}$/.test(phone)?phone:phone;
      var share='https://wa.me/?text='+encodeURIComponent('🤝 SewaAstra पर मुझे refer करो! मेरा refer code: '+code+' — पहले 5 पूरे orders पर referrer को 1000 🪙 coins मिलते हैं (100 coin = ₹10 ऑर्डर पर छूट)। App: ');
      var rBy=u.refBy?'✔ Refer code applied ('+u.refBy+(u.refKind==='partner'?' — Partner': '')+')':'';

      var html='<div style="max-height:74vh;overflow-y:auto;text-align:left;font-size:12px;line-height:1.6;">'+
      '<div style="display:flex;gap:10px;">'+
        '<div style="flex:1;background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;border-radius:16px;padding:12px;text-align:center;"><div style="font-size:9px;font-weight:800;opacity:.85;letter-spacing:1px;">💰 SW WALLET (₹)</div><div style="font-size:24px;font-weight:900;margin-top:3px;">₹'+(Number(u.swBal)||0).toLocaleString('en-IN')+'</div><div style="font-size:8.5px;opacity:.85;">हर पूरे order पर +₹5</div></div>'+
        '<div style="flex:1;background:linear-gradient(135deg,#b07800,#ffb300);color:#fff;border-radius:16px;padding:12px;text-align:center;"><div style="font-size:9px;font-weight:800;opacity:.9;letter-spacing:1px;">🪙 REWARD COINS</div><div style="font-size:24px;font-weight:900;margin-top:3px;">'+(Number(u.coins)||0).toLocaleString('en-IN')+'</div><div style="font-size:8.5px;opacity:.9;">100 coin = ₹10 छूट</div></div>'+
      '</div>'+
      '<div style="background:#fff8f0;border:1px dashed #ffb300;border-radius:12px;padding:9px 11px;margin-top:10px;font-size:11px;">💡 Checkout पर wallet & coins <b>अपने आप</b> लग जाते हैं (coupon के बाद)। SW wallet cash-out भी कर सकते हैं।</div>'+
      '<div style="display:flex;gap:8px;margin-top:10px;">'+
        '<button onclick="c44Wd()" style="flex:1;border:none;background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;padding:11px;border-radius:12px;font-weight:800;font-size:11.5px;cursor:pointer;">💸 SW Cash-Out</button>'+
        '<button onclick="c44History()" style="flex:1;border:none;background:#0f1626;color:#ffd700;padding:11px;border-radius:12px;font-weight:800;font-size:11.5px;cursor:pointer;">📜 Ledger</button></div>'+
      '<div style="margin-top:14px;border-top:2px solid #f0f0f0;padding-top:10px;">'+
        '<div style="font-weight:900;font-size:13px;">🤝 Refer & Earn — 1000 🪙 तक</div>'+
        '<div style="color:#666;margin-top:3px;">अपना कोड <b style="color:var(--primary);">'+wEsc(code)+'</b> दोस्तों को दो। उनके पूरे orders पर आपको मिलेंगे:</div>'+
        '<div style="font-size:11px;margin-top:5px;line-height:1.9;">'+[100,100,150,150,500].map(function(v,i){ return (i<paid?'<b style="color:#15a04a;">✓</b> ':'<b style="color:#ccc;">'+ (i+1) +'.</b> ')+'Order #'+(i+1)+' complete → <b style="color:#b07800;">'+v+' coin</b>'; }).join('<br>')+'</div>'+
        '<div style="font-size:10.5px;color:#15a04a;font-weight:800;margin-top:5px;">अब तक '+(paid||0)+'/5 • कुल '+prog+' coin मिले</div>'+
        '<a href="'+share+'" target="_blank" style="display:block;text-align:center;margin-top:9px;background:#25d366;color:#fff;text-decoration:none;padding:11px;border-radius:12px;font-weight:800;font-size:12px;" rel="noopener noreferrer">💬 WhatsApp पर share करें</a>'+
        '<div style="margin-top:12px;background:#f6f6f6;border-radius:12px;padding:9px 11px;">'+(rBy?rBy:'<span style="font-size:11px;">किसी ने आपको <b>refer code</b> भेजा है? नीचे डालें — 1000 coin कमाने का मौका:</span><div style="display:flex;gap:7px;margin-top:7px;"><input id="c44RefI" placeholder="Refer code (मोबाइल नं.)" style="flex:1;border:1px solid #ddd;border-radius:9px;padding:9px;font-size:12px;outline:none;"><button onclick="c44ApplyRef()" style="border:none;background:var(--primary);color:#fff;padding:9px 14px;border-radius:9px;font-weight:800;cursor:pointer;font-size:12px;">लागू करें</button></div>')+'</div>'+
      '</div></div>';
      showAlert('💰 Wallet • Coins • Refer', html);
    }).catch(function(e){ showAlert('त्रुटि', e.message); });
  };
  window.c44History=function(){
    var led=(wC.led||[]).slice(-25).reverse();
    showAlert('📜 Wallet Ledger', (led.length?led.map(ledRow).join(''):'<div style="text-align:center;color:#888;padding:20px;">अभी कोई entry नहीं</div>'));
  };
  window.c44Wd=function(){
    var bal=Number(wC.swBal)||0;
    if(bal<10) return showAlert('कम balance','Cash-out के लिए कम से कम ₹10 SW wallet चाहिए (हर पूरे order पर +₹5)।');
    var html='<div style="text-align:left;font-size:12px;">'+
      '<div style="background:#eef4ff;border-radius:12px;padding:10px 12px;">उपलब्ध SW wallet: <b style="color:#0d47a1;font-size:15px;">₹'+bal+'</b><br><span style="font-size:10px;color:#666;">Payout UPI पर आएगा — Admin verify करके भेजते हैं।</span></div>'+
      '<div style="margin-top:10px;font-weight:700;">UPI ID</div><input id="c44WU" placeholder="yourname@upi" style="width:100%;border:1px solid #ddd;border-radius:10px;padding:10px;font-size:13px;margin-top:4px;outline:none;box-sizing:border-box;">'+
      '<div style="margin-top:9px;font-weight:700;">₹ राशि (max ₹'+bal+')</div><input id="c44WA" type="number" min="10" max="'+bal+'" value="'+bal+'" style="width:100%;border:1px solid #ddd;border-radius:10px;padding:10px;font-size:13px;margin-top:4px;outline:none;box-sizing:border-box;">'+
      '<button onclick="c44WdGo()" style="width:100%;margin-top:13px;border:none;background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;padding:13px;border-radius:13px;font-weight:900;cursor:pointer;">💸 Cash-Out Request भेजें</button></div>';
    showAlert('💸 SW Wallet Cash-Out', html);
  };
  window.c44WdGo=function(){
    var upi=(document.getElementById('c44WU')||{value:''}).value.trim();
    var a=parseInt((document.getElementById('c44WA')||{value:'0'}).value,10);
    if(!/^[\w.\-]{2,}@[a-zA-Z]{2,}$/.test(upi)) return showAlert('UPI गलत','सही UPI ID डालें — जैसे name@okhdfcbank');
    if(!(a>=10)) return showAlert('राशि','कम से कम ₹10 डालें');
    if(a>(Number(wC.swBal)||0)) return showAlert('राशि','बैलेंस से ज़्यादा नहीं');
    closeCustomAlert();
    /* 🔒 customer withdrawal भी server से */ SWSec.call('requestWithdrawal',{amt:a,upi:upi}); void ({amt:a,upi:upi,status:'Requested',kind:'customer',by:wKey(),ts:Date.now(),at:new Date().toLocaleString('en-IN')})
      .then(function(){ showToast('💸 Request भेज दी! Admin जल्द payout करेंगे'); c44Wallet(); })
      .catch(function(e){ showAlert('त्रुटि', e.message); });
  };
  window.c44ApplyRef=function(){
    var code=(document.getElementById('c44RefI')||{value:''}).value.trim();
    if(!code) return;
    if(wC.refBy) return showAlert('पहले से लगा है','आपका refer code पहले ही लग चुका है।');
    /* detect partner/customer */
    Promise.all([
      FS.collection('partners').doc(code).get().catch(function(){return null;}),
      FS.collection('users').doc(code).get().catch(function(){return null;})
    ]).then(function(r){
      var kind=null;
      if(r[0]&&r[0].exists) kind='partner';
      else if(r[1]&&r[1].exists) kind='customer';
      if(!kind) return showAlert('Code नहीं मिला','यह refer code सही नहीं है। दोबारा जाँच करें।');
      FS.collection('users').doc(wKey()).set({refBy:code,refKind:kind},{merge:true}).then(function(){
        wC.refBy=code; wC.refKind=kind;
        closeCustomAlert();
        showAlert('🎉 Refer code लग गया!',(kind==='partner'?'Partner':'दोस्त')+' <b>'+wEsc(code)+'</b> से जुड़े!<br><br>अब आपके पूरे orders पर referrer को coins मिलेंगे।');
        c44Wallet();
      }).catch(function(e){ showAlert('त्रुटि', e.message); });
    }).catch(function(e){ showAlert('त्रुटि', e.message); });
  };
  var _crA=window.custReqAction;
  if(typeof _crA==='function'){
    window.custReqAction=function(type){
      if(type==='Wallet') return c44Wallet('wallet');
      if(type==='Referral') return c44Wallet('refer');
      return _crA(type);
    };
  }

  /* ═══ 5) CHECKOUT — wallet/coins auto apply ═══ */
  var wUse={sw:0,coinU:0,coinV:0};      /* coinU=coins, coinV=₹ value */
  var wSwOn=true, wCoinOn=true;
  function wBox(){
    try{
      var anchor=document.getElementById('couponMsg');
      if(!anchor||document.getElementById('c44WBox')) return;
      var host=anchor.closest('.cart-card');
      if(!host) return;
      var card=document.createElement('div');
      card.className='cart-card'; card.id='c44WBox';
      card.style.background='#f4f8ff'; card.style.border='1px dashed #1976d2';
      card.innerHTML=
      '<label style="font-size:12px;font-weight:800;color:#0d47a1;">💰 SewaAstra Wallet & Coins — छूट अपने आप लागू होगी</label>'+
      '<div style="margin-top:9px;background:#fff;border:1px solid #e5ecf8;border-radius:11px;padding:9px 11px;">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;"><span style="font-size:12px;">💵 SW Wallet (-₹) <b id="c44SwAv" style="color:#0d47a1;">₹0</b></span>'+
        '<span style="display:flex;align-items:center;gap:6px;"><span style="font-size:10px;color:#888;">use?</span><input type="checkbox" id="c44SwT" checked></span></div>'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:7px;padding-top:7px;border-top:1px dashed #e5ecf8;"><span style="font-size:12px;">🪙 Coins <b id="c44CoAv" style="color:#b07800;">0</b> <span style="font-size:9px;color:#999;">(100=₹10)</span></span>'+
        '<span style="display:flex;align-items:center;gap:6px;"><span style="font-size:10px;color:#888;">use?</span><input type="checkbox" id="c44CoT" checked></span></div>'+
        '<div id="c44WNote" style="font-size:10px;color:#0d47a1;font-weight:700;margin-top:7px;line-height:1.5;">—</div>'+
      '</div>';
      host.insertAdjacentElement('afterend',card);
      var swT=document.getElementById('c44SwT'), coT=document.getElementById('c44CoT');
      swT.onchange=function(){ wSwOn=swT.checked; wCartRefresh(); };
      coT.onchange=function(){ wCoinOn=coT.checked; wCartRefresh(); };
    }catch(e){}
  }
  function wBillBase(){
    try{
      var sub=0; (typeof cart!=='undefined'?cart:[]).forEach(function(i){ sub+=(Number(i.p)||0)*((i.qty)||1); });
      return Math.max(0, sub-(Number(window.appliedDiscount)||0));
    }catch(e){ return 0; }
  }
  function wCartRefresh(){
    try{
      var b=wBillBase();
      var swAv=Math.max(0,Math.floor(Number(wC.swBal)||0));
      var coAv=Math.max(0,Math.floor(Number(wC.coins)||0));
      var swU=wSwOn?Math.min(swAv,b):0;
      var rem=Math.max(0,b-swU);
      var blocks=wCoinOn?Math.min(Math.floor(coAv/100),Math.floor(rem/10)):0;
      var coU=blocks*100, coV=blocks*10;
      wUse={sw:swU,coinU:coU,coinV:coV};
      var fTotal=document.getElementById('fTotal'); var sRow=document.getElementById('wSwRow'), cRow=document.getElementById('wCoinRow');
      if(!sRow||!cRow){ wInjectBillRows(); sRow=document.getElementById('wSwRow'); cRow=document.getElementById('wCoinRow'); }
      if(sRow) sRow.innerHTML='<span>SW Wallet छूट</span> <span style="color:#0d47a1;">-₹'+swU+'</span>';
      if(cRow) cRow.innerHTML='<span>🪙 Coins छूट ('+coU+' coin)</span> <span style="color:#b07800;">-₹'+coV+'</span>';
      var base=document.getElementById('sTotal');
      var final=(base?Number((document.getElementById('sTotal')||{innerText:'₹0'}).innerText.replace(/[^0-9]/g,''))||0:0);
      /* recompute exact */
      var exact=(wBillBase()+10)-swU-coV;
      if(exact<10) exact=10;
      var fTot=document.getElementById('fTotal'); if(fTot) fTot.innerText='₹'+(exact.toLocaleString?exact.toLocaleString('en-IN'):exact);
      var note=document.getElementById('c44WNote');
      if(note) note.innerText=(swU||coV)?('इस ऑर्डर पर बचत: '+(swU?('SW ₹'+swU+' '):'')+(coV?('+ Coins ₹'+coV+' ('+coU+' coin)'):'')+' ✅'):'कोई छूट नहीं — पहले wallet/coins कमाएँ (order complete पर +₹5)।';
      var sAv=document.getElementById('c44SwAv'); if(sAv) sAv.innerText='₹'+(swAv||0);
      var cAv=document.getElementById('c44CoAv'); if(cAv) cAv.innerText=(coAv||0)+'';
    }catch(e){}
  }
  function wInjectBillRows(){
    try{
      var fr=document.getElementById('fTotal');
      if(!fr||document.getElementById('wSwRow')) return;
      var bill=fr.closest('.cart-card'); if(!bill) return;
      var sw=document.createElement('div'); sw.className='bill-row'; sw.style.color='#0d47a1'; sw.id='wSwRow'; sw.innerHTML='<span>SW Wallet छूट</span> <span>-₹0</span>';
      var co=document.createElement('div'); co.className='bill-row'; co.style.color='#b07800'; co.id='wCoinRow'; co.innerHTML='<span>🪙 Coins छूट (0 coin)</span> <span>-₹0</span>';
      var tr=fr.closest('.total-amt')||bill.querySelector('.total-amt');
      bill.insertBefore(sw,tr); bill.insertBefore(co,tr);
    }catch(e){}
  }
  try{
    var _chk=window.checkout;
    if(typeof _chk==='function'){
      window.checkout=function(){ _chk(); setTimeout(function(){ try{ wBox(); FS.collection('users').doc(wKey()).get().then(function(d){ if(d.exists) wC=Object.assign(wC,d.data()); wCartRefresh(); }).catch(function(){ wCartRefresh(); }); }catch(e){} },80); };
    }
  }catch(e){}
  try{
    var _rc44=window.renderCart;
    if(typeof _rc44==='function') window.renderCart=function(){ _rc44(); setTimeout(wCartRefresh,20); };
  }catch(e){}

  /* ═══ 6) handleFinalOrder — wallet/coins डिडक्ट + rewards field ═══ */
  window.handleFinalOrder=function(){
    try{
      var address=(document.getElementById('manualAddr')||{value:''}).value.trim();
      var mobile=(document.getElementById('altMobile')||{value:''}).value.trim();
      var date=(document.getElementById('cartDate')||{value:''}).value;
      var time=(document.getElementById('cartTime')||{value:''}).value;
      var remark=(document.getElementById('cartRemark')||{value:''}).value.trim();
      var mapsLink=(document.getElementById('googleMapsLink')||{value:''}).value;
      if(!address) return showAlert('पता आवश्यक है','कृपया अपनी डिलीवरी लोकेशन या पता दर्ज करें');
      if(!selectedMode) return showAlert('भुगतान मोड चुनें','कृपया Cash या Online भुगतान का तरीका चुनें');
      if(typeof cart==='undefined'||!cart.length) return showAlert('कार्ट खाली है','पहले कोई सेवा जोड़ें');

      var subtotal=cart.reduce(function(a,c){ return a+(Number(c.p)||0)*((c.qty)||1); },0);
      var bill=Math.max(0, subtotal-(Number(window.appliedDiscount)||0));
      /* caps fresh (UI के state को मान्य करते हुए) */
      var swU=wSwOn?Math.min(Math.floor(Number(wC.swBal)||0),bill):0;
      var rem=Math.max(0,bill-swU);
      var blocks=wCoinOn?Math.min(Math.floor((Number(wC.coins)||0)/100),Math.floor(rem/10)):0;
      var coU=blocks*100, coV=blocks*10;
      var finalAmt=Math.max(10,(bill+10)-swU-coV);
      wUse={sw:swU,coinU:coU,coinV:coV};

      var oid='SW'+Math.floor(100000+Math.random()*900000);
      var userMobile=mobile||getIdent()||'';
      var order={
        id:oid, uid:getUID(), mobile:userMobile,
        items:cart.map(function(i){ return {n:i.n,p:Number(i.p)||0,qty:(i.qty||1),cat:i.cat||'',catName:i.catName||'',selectedSub:(i.selectedSub||''),custom:!!i.custom}; }),
        subtotal:subtotal, discount:(Number(window.appliedDiscount)||0), total:finalAmt,
        address:address, date:date, time:time, remark:remark, mode:selectedMode, maps:mapsLink||'',
        rewards:{sw:swU,coins:coU,coinVal:coV},
        cats:(function(){ var s={},out=[]; (typeof cart!=='undefined'?cart:[]).forEach(function(i){ var k=i.cat||'general',nn=i.catName||'General'; if(!s[k]){s[k]=1;out.push({key:k,name:nn});} }); return out; })(),
        status:'Order Placed', rated:false,
        loc:(typeof userCoords!=='undefined'?{lat:userCoords.lat,lon:userCoords.lon}:null),
        createdAt:Date.now(), timestamp:new Date().toLocaleString('hi-IN')
      };
      showLoader('ऑर्डर सेव हो रहा है...');
      FS.collection('orders').doc(oid).set(order).then(function(){
        hideLoader();
        /* wallet/coins deduct */
        try{ wDeduct(oid,swU,coU); }catch(e){}
        try{
          var hist=JSON.parse(localStorage.getItem('sw_order_history'))||[]; hist.unshift(order); localStorage.setItem('sw_order_history',JSON.stringify(hist.slice(0,50)));
        }catch(e){}
        var waMsg='*🚀 New SewaAstra Booking!*%0A🆔 Order ID: '+oid+'%0A👤 User: '+userMobile+'%0A📦 Items: '+cart.map(function(i){return i.n+' (x'+(i.qty||1)+')';}).join(', ')+'%0A💰 Total: ₹'+finalAmt+' ('+selectedMode+')%0A📍 Address: '+address+'%0A🗺️ Map: '+mapsLink+'%0A📅 '+date+' at '+time+'%0A📝 '+(remark||'None');
        try{ document.getElementById('fullCartPanel').style.display='none'; }catch(e){}
        cart=[]; window.cart=cart;
        try{ document.getElementById('bCount').innerText='0'; }catch(e){}
        appliedDiscount=0;
        var extra='';
        if(selectedMode==='Online'&&CLOUD_CONFIG.upiId){
          var upi='upi://pay?pa='+encodeURIComponent(CLOUD_CONFIG.upiId)+'&pn=SewaAstra&am='+finalAmt+'&cu=INR&tn='+oid;
          extra='<br><a href="'+upi+'" style="display:inline-block;margin-top:10px;background:#15a04a;color:#fff;padding:10px 18px;border-radius:10px;text-decoration:none;font-weight:bold;">💳 UPI से ₹'+finalAmt+' Pay करें</a>';
        }
        var saved='';
        if(swU||coU) saved='<br><span style="font-size:11px;color:#0d47a1;font-weight:700;">💰 Wallet/Coins से बचत: '+(swU?'SW ₹'+swU+' ':'')+(coU?('Coins ₹'+coV+' ('+coU+' coin)'):'')+'</span>';
        showAlert('बुकिंग सफल! 🎉','आपका ऑर्डर <b>'+oid+'</b> ☁️ cloud में सेव हो गया है!'+saved+'<br>स्टेटस अपडेट यहीं मिलेंगे।'+extra+'<br><br>💡 पूरा होने पर +₹5 SW wallet में मिलेगा!');
        try{ window.startMyOrdersListener&&startMyOrdersListener(); }catch(e){}
      }).catch(function(e){ hideLoader(); showAlert('त्रुटि','ऑर्डर सेव नहीं हो सका: '+e.message); });
    }catch(e){ showAlert('त्रुटि', e.message); }
  };
  function wDeduct(oid,swU,coU){
    try{
      var ref=FS.collection('users').doc(wKey());
      FS.runTransaction(function(tx){
        return tx.get(ref).then(function(d){
          var u=d.exists?d.data():{swBal:0,coins:0,led:[]};
          var sw=Math.max(0,(Number(u.swBal)||0)-swU);
          var co=Math.max(0,(Number(u.coins)||0)-coU);
          var led=u.led||[];
          var now=new Date().toLocaleString('en-IN');
          if(swU) led=led.concat([{k:'sw',amt:-swU,note:'Order '+oid+' पर wallet use',at:now}]);
          if(coU) led=led.concat([{k:'coin',amt:-coU,note:'Order '+oid+' पर coins redeem',at:now}]);
          led=led.slice(-30);
          tx.set(ref,{swBal:sw,coins:co,led:led},{merge:true});
          wC.sw=sw; wC.coins=co; wC.led=led;
        });
      }).catch(function(){});
    }catch(e){}
  }

  /* ═══ 7) REWARD ENGINE — Completed order → +₹5 SW (+referrer milestone) ═══ */
  var REW={cs:[100,100,150,150,500], pt:[10,10,15,15,50]};
  function wReward(oid){
    try{
      var myRef=FS.collection('users').doc(wKey());
      FS.runTransaction(function(tx){
        return tx.get(FS.collection('orders').doc(oid)).then(function(od){
          var o=od.exists?od.data():null;
          if(!o||o.status!=='Completed'||o.swRewarded) return null;
          return tx.get(myRef).then(function(md){
            var u=md.exists?md.data():{swBal:0,coins:0,led:[],refBy:'',refKind:''};
            var sw=Math.max(0,(Number(u.swBal)||0)+5);
            var led=(u.led||[]).concat([{k:'sw',amt:5,note:'Order '+oid+' complete → +₹5',at:new Date().toLocaleString('en-IN')}]).slice(-30);
            var upd={swBal:sw,led:led};
            var refFlag=false;
            if(u.refBy&&u.refKind){
              var rref=u.refKind==='partner'?FS.collection('partners').doc(u.refBy):FS.collection('users').doc(u.refBy);
              return tx.get(rref).then(function(rd){
                var rdata=rd.exists?rd.data():null;
                if(rd.exists){
                  var paid=Number(rdata.refPaid)||0;
                  if(paid<5){
                    if(u.refKind==='customer'){
                      var coin=REW.cs[paid]||0;
                      var rled=(rdata.led||[]).concat([{k:'coin',amt:coin,note:'Referral order '+oid+' complete',at:new Date().toLocaleString('en-IN')}]).slice(-30);
                      tx.set(rref,{refPaid:paid+1,coins:Math.max(0,(Number(rdata.coins)||0)+coin),led:rled},{merge:true});
                    }else{
                      var rs=REW.pt[paid]||0;
                      var rled2=(rdata.led||[]).concat([{k:'sw',amt:rs,note:'Referral order '+oid+' complete → +₹'+rs,at:new Date().toLocaleString('en-IN')}]).slice(-30);
                      tx.set(rref,{refPaid:paid+1,refBonus:Math.max(0,(Number(rdata.refBonus)||0)+rs),led:rled2},{merge:true});
                    }
                    refFlag=true;
                  }
                }
                tx.set(myRef,upd,{merge:true});
                tx.update(FS.collection('orders').doc(oid),{swRewarded:true,swRewardAt:Date.now(),refRewarded:refFlag});
                return true;
              });
            }
            tx.set(myRef,upd,{merge:true});
            tx.update(FS.collection('orders').doc(oid),{swRewarded:true,swRewardAt:Date.now(),refRewarded:false});
            return true;
          });
        });
      }).then(function(done){
        if(done) setTimeout(function(){ try{ showToast('💰 +₹5 SW wallet में जुड़ गया!'); }catch(e){} },600);
      }).catch(function(e){});
    }catch(e){}
  }
  var wDone={};
  function wWatch(){
    try{
      if(!window.myOrdersQuery) return;
      if(!wKey()) return;
      if(window.__c44Watch) return; window.__c44Watch=1;
      myOrdersQuery().onSnapshot(function(snap){
        snap.docs.forEach(function(d){
          var o=d.data();
          if(o.status==='Completed'&&!o.swRewarded&&!wDone[o.id]){ wDone[o.id]=1; wReward(d.id); }
        });
      },function(){});
    }catch(e){}
  }

  /* ═══ 8) EDIT-POPUP — customer को दिखे क्या update हुआ (#8) ═══ */
  var seenEdits={};
  try{ seenEdits=JSON.parse(localStorage.getItem('c44seen')||'{}'); }catch(e){ seenEdits={}; }
  function wEditWatch(){
    try{
      if(!window.myOrdersQuery) return;
      if(window.__c44EW) return; window.__c44EW=1;
      myOrdersQuery().onSnapshot(function(snap){
        snap.docs.forEach(function(d){
          var o=d.data();
          if(o.wUOtp&&o.wUOtpAt&&(Date.now()-(o.wUOtpAt||0))<60000){
            if(!seenEdits['otp'+o.id]||seenEdits['otp'+o.id]!==o.wUOtpAt){
              seenEdits['otp'+o.id]=o.wUOtpAt;
              try{ localStorage.setItem('c44seen',JSON.stringify(seenEdits)); }catch(e){}
              showToast('🔐 Partner काम बदलना चाहता है — नया OTP: '+o.wUOtp+' (left-नीचे)');
            }
          }
          if(o.edited&&o.editedAt&&(!seenEdits['e'+o.id]||seenEdits['e'+o.id]!==o.editedAt)){
            seenEdits['e'+o.id]=o.editedAt;
            try{ localStorage.setItem('c44seen',JSON.stringify(seenEdits)); }catch(e){}
            setTimeout(function(){ wEditPopup(o); },600);
          }
        });
      },function(){});
    }catch(e){}
  }
  function wEditPopup(o){
    try{
      var its=(o.items||[]).map(function(i){ return '• '+wEsc(i.n)+' ×'+(i.qty||1)+' <span style="color:#0d47a1;">₹'+((Number(i.p)||0)*(i.qty||1))+'</span>'; }).join('<br>');
      var nv=Number(o.total)||0;
      showAlert('✏️ ऑर्डर में बदलाव हुआ','<div style="text-align:left;font-size:12px;line-height:1.8;">Order <b>'+wEsc(o.id)+'</b> — Partner (visit पर) ने काम update किया:<br><br>🛠️ <b>नए items:</b><br>'+its+'<br><div style="border-top:1px dashed #ddd;margin:8px 0;"></div>💰 <b>नया Total: ₹'+(nv.toLocaleString?nv.toLocaleString('en-IN'):nv)+'</b>'+(o.editedAt?'<br><span style="font-size:10px;color:#888;">'+new Date(o.editedAt).toLocaleString('en-IN')+' • '+wEsc(o.editedBy||'Partner')+'</span>':'')+'<br><br><span style="color:#0d47a1;font-size:11px;">Bill/history में भी live update हो गया है।</span></div>');
    }catch(e){}
  }
  setTimeout(wEditWatch,3000);

  console.log('%c 💰🪙⭐ CUSTOMER v4.4 — WALLET + COINS + REFER + SERVICE RATING + EDIT-POPUP ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 27 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([27, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 28 ═══ */
try {
/* ═══════════════ CUSTOMER v4.6 — 🌐 GOOGLE TRANSLATE (A–Z पूरी App) + ⚡ 5-sec AUTO REFRESH (data reset नहीं) ═══════════════ */
(function(){
  if(window.__c46) return; window.__c46=1;
var LGS=[['hi','हिन्दी'],['en','English']];
  var _ready=false,_loading=false;

  function host(){
    var h=document.getElementById('swGtEl');
    if(!h){ h=document.createElement('div'); h.id='swGtEl';
      h.style.cssText='position:absolute;top:-9999px;left:-9999px;width:8px;height:8px;opacity:.01;overflow:hidden;pointer-events:none;';
      document.body.appendChild(h); }
    return h;
  }
  function load(){
    if(_loading) return; _loading=true;
    try{
      window.swGtCb=function(){ try{ if(window.google&&google.translate){ new google.translate.TranslateElement({pageLanguage:'hi',autoDisplay:false,includedLanguages:'hi,en',layout:google.translate.TranslateElement.InlineLayout.SIMPLE},'swGtEl'); _ready=true; } }catch(e){} };
      if(document.querySelector('script[src*="translate_a/element.js"]')){ _loading=false; return; }
      var sc=document.createElement('script');
      sc.src='https://translate.google.com/translate_a/element.js?cb=swGtCb';
      sc.onerror=function(){ _loading=false; try{ showToast('🌐 Translate load नहीं हुआ — internet check करें'); }catch(e){} };
      document.head.appendChild(sc);
    }catch(e){ _loading=false; }
  }
  function combo(){ try{ var el=host(); var c=el.querySelector('.goog-te-combo'); return c; }catch(e){ return null; } }
  function panelHTML(){
    return '<div style="max-width:430px;margin:0 auto;background:#fff;border-radius:22px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.45);animation:ain46 .22s">'+
    '<div style="background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;padding:16px;display:flex;justify-content:space-between;align-items:center;"><div><b style="font-size:15px;">🌐 पूरी App को भाषा में बदलें</b><br><span style="font-size:10px;opacity:.9;">Google Translate — A to Z सब बदलता है</span></div><span style="font-size:22px;cursor:pointer;" onclick="swGtHide()">✕</span></div>'+
    '<div style="padding:12px 14px;max-height:62vh;overflow-y:auto;">'+
      '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;">'+
        LGS.map(function(l){ return '<button type="button" onclick="swGtSet(\''+l[0]+'\')" style="padding:12px 8px;border-radius:11px;border:1.5px solid #e3ecfa;background:#f4f8ff;color:#0d3b66;font-weight:800;font-size:12.5px;cursor:pointer;">'+l[1]+'</button>'; }).join('')+
      '</div>'+
    '</div>'+
    '<div style="padding:10px 16px 14px;font-size:9.5px;color:#888;border-top:1px dashed #ddd;text-align:center;">💡 कोई भी बनाया हुआ data (cart/order/forms) reset नहीं होता — सिर्फ भाषा बदलती है</div>'+
    '</div>';
  }
  function ovr(){
    var o=document.getElementById('swGtOv');
    if(!o){ o=document.createElement('div'); o.id='swGtOv';
      o.style.cssText='position:fixed;inset:0;z-index:9999992;display:none;align-items:center;justify-content:center;background:rgba(5,10,25,.55);padding:16px;';
      document.body.appendChild(o);
      var st=document.createElement('style'); st.id='swGtSt';
      st.textContent='@keyframes ain46{from{transform:scale(.92) translateY(18px);opacity:0}to{transform:none;opacity:1}}';
      document.head.appendChild(st);
    }
    return o;
  }
  window.swGtShow=function(){
    try{ if(!_ready) load(); var o=ovr(); o.innerHTML='<div style="width:100%;">'+panelHTML()+'</div>'; o.style.display='flex';
      if(!_ready){ try{ showToast('🌐 Translate तैयार हो रहा है... थोड़ी देर में दोबारा चुनें'); }catch(e){} }
    }catch(e){}
  };
  window.swGtHide=function(){ try{ var o=ovr(); o.style.display='none'; }catch(e){} };
  ovr();
  window.swGtSet=function(code){
    try{
      var c=combo();
      if(!c){ load(); try{ showToast('🌐 Google Translate load हो रहा है — 2 सेकंड में दोबारा दबाएँ'); }catch(e){} return; }
      c.value=code;
      try{ c.dispatchEvent(new Event('change',{bubbles:true})); }catch(e){}
      swGtHide();
      try{ showToast('🌐 भाषा बदली गई — पूरी App translate हो रही है'); }catch(e){}
    }catch(e){}
  };
  /* header quick chip */
  try{
    var hp=document.getElementById('headerProfile');
    if(false&&hp&&!document.getElementById('hdGt')){
      var g=document.createElement('div'); g.id='hdGt';
      g.title='🌐 Translate / भाषा';
      g.style.cssText='width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:17px;cursor:pointer;background:var(--primary-light);border:1px solid var(--primary);';
      g.innerHTML='🌐';
      g.onclick=function(){ swGtShow(); };
      hp.parentNode.insertBefore(g,hp);
    }
  }catch(e){}

  /* ═══ ⚡ 5-SEC AUTO REFRESH — admin/catalogue live, par भरा data नहीं मिटता ═══ */
  try{ var _ld46=window.load; if(typeof _ld46==='function') window.load=function(k){ try{ window.__curCat=k; }catch(e){} _ld46(k); }; }catch(e){}
  function softRefresh(){
    try{
      if(document.hidden) return;
      FS.collection('app_config').doc('main').get().then(function(d){
        if(!d.exists) return;
        var x=d.data(), u=Number(x.updatedAt)||0;
        if(u && window.__cfgT && u<=window.__cfgT) return;
        window.__cfgT=u;
        try{ if(typeof applyCloudConfig==='function') applyCloudConfig(x); }catch(e){}
        /* reload catalog sirf तभी जब search खाली हो (user का typing/search reset न हो) */
        var srchEl=document.getElementById('srch');
        var busy=!!(srchEl&&srchEl.value&&srchEl.value.trim().length);
        var k=window.__curCat;
        if(k&&!busy){ try{ if(typeof window.load==='function') window.load(k); }catch(e){} }
      }).catch(function(){});
    }catch(e){}
  }
  setInterval(softRefresh,5000);
  setTimeout(function(){ try{ FS.collection('app_config').doc('main').get().then(function(d){ if(d.exists) window.__cfgT=Number((d.data().updatedAt)||0); }).catch(function(){}); }catch(e){} },3000);
  console.log('%c 🌐⚡ CUSTOMER v4.6 — GOOGLE TRANSLATE + AUTO REFRESH ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 28 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([28, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 29 ═══ */
try {
/* ═══════════════ CUSTOMER v4.7 — REAL FULL-APP TRANSLATE + ORIGINAL COMPANY BILL (SewaAstra Steel Pvt Ltd) + SOS CLOSE ═══════════════ */
(function(){
  if(window.__c47) return; window.__c47=1;

  /* ─────────────────────── 1) REAL TRANSLATE ENGINE ───────────────────────
     Google Translate (पूरी app) + बिल्ट-इन dictionary scan (offline भी A–Z scan).
     Har DOM change पर फिर scan होता है → नया content भी translate दिखे। */
  var DICT={
    'नया ऑर्डर':'New Order','मेरे Active काम':'My Active Jobs','मेरे काम':'My Jobs','काम पूरा हुआ':'Work Completed','काम शुरू किया':'Work Started',
    'ऑर्डर प्लेस':'Place Order','ऑर्डर कैंसिल':'Cancel Order','सेवा रद्द':'Service Cancelled','बुकिंग सफल':'Booking Successful','ऑर्डर सफलतापूर्वक':'Order Successfully',
    'आपका ऑर्डर':'Your Order','ऑर्डर आईडी':'Order ID','कार्ट खाली है':'Cart is empty','कार्ट में जोड़ा':'Added to cart','चेकआउट करें':'Checkout','भुगतान करें':'Pay Now',
    'ऑर्डर इतिहास':'Order History','स्टेटस अपडेट':'Status Update','लाइव ट्रैकिंग':'Live Tracking','रास्ते में':'On the Way','स्वीकृत':'Accepted','पूर्ण':'Completed','रद्द':'Cancelled',
    'ऑर्डर':'Order','सेवा':'Service','सर्विस':'Service','सर्विसेज':'Services','कार्ट':'Cart','इतिहास':'History','काम':'Job/Work','बिल':'Bill','भुगतान':'Payment','पेमेंट':'Payment',
    'मोबाइल नंबर':'Mobile Number','नंबर':'Number','पता':'Address','तारीख':'Date','समय':'Time','कुल':'Total','छूट':'Discount','कूपन':'Coupon','राशि':'Amount','कीमत':'Price',
    'प्रोफ़ाइल':'Profile','प्रोफाइल':'Profile','सेटिंग्स':'Settings','मदद':'Help','सहायता':'Support','भाषा':'Language','अनुवाद':'Translate','ऐप':'App','धन्यवाद':'Thank You',
    'रद्द करें':'Cancel','सेव करें':'Save','जोड़ें':'Add','हटाएँ':'Remove','देखें':'View','खोलें':'Open','बंद करें':'Close','लॉगिन':'Login','लॉगआउट':'Logout','रजिस्टर':'Register',
    'एक बार फिर':'Retry','फिर से':'Again','जारी रखें':'Continue','पहले':'Before/First','बाद में':'Later','कम':'Less','ज्यादा':'More','हाँ':'Yes','नहीं':'No','खोजें':'Search',
    'आज':'Today','कल':'Tomorrow','आपका':'Your','आपकी':'Your','मेरा':'My','मेरी':'My','हमारा':'Our','कृपया':'Please','त्रुटि':'Error','सफल':'Success','नया':'New',
    'ऑनलाइन':'Online','ऑफलाइन':'Offline','स्वीकार करें':'Accept','अस्वीकार करें':'Reject','कन्फर्म करें':'Confirm','कोड':'Code','उपलब्ध':'Available','बटन':'Button',
    'पैसे':'Money','रुपये':'Rupees','वॉलेट':'Wallet','सिक्के':'Coins','कमाई':'Earnings','निकालें':'Withdraw','जमा':'Deposit','बैलेंस':'Balance','रेफर':'Refer','दोस्त':'Friend',
    'शेयर करें':'Share','रेटिंग':'Rating','समीक्षा':'Review','टिप्पणी':'Comment','अनुभव':'Experience','स्टार':'Star','तुरंत':'Immediately','कॉल करें':'Call','चैट':'Chat',
    'सूचना':'Notice','नोटिफिकेशन':'Notification','सुरक्षा':'Security','सहमत':'Agree','नियम':'Rules','शर्तें':'Terms','नीति':'Policy','पढ़ें':'Read','कमीशन':'Commission','कमिशन':'Commission',
    'जीएसटी':'GST','टैक्स':'Tax','इनवॉइस':'Invoice','शहर':'City','पिन कोड':'PIN Code','क्षेत्र':'Area','दूरी':'Distance','नज़दीक':'Nearby','मिनट':'Minutes','घंटे':'Hours',
    'किलोमीटर':'Kilometer','वाहन':'Vehicle','कौशल':'Skill','अनुभव':'Experience','दस्तावेज़':'Documents','अपलोड':'Upload','फोटो':'Photo','गैलरी':'Gallery','नाम':'Name',
    'आधार':'Aadhaar','सबमिट करें':'Submit','मंज़ूरी':'Approval','लंबित':'Pending','अनुमोदित':'Approved','वेरिफाई':'Verify','ओटीपी':'OTP','लाइव':'Live','जीपीएस':'GPS',
    'अलर्ट':'Alert','काम बदलें':'Change Work','अतिरिक्त':'Extra','बदलाव':'Update','हैंडलिंग':'Handling','चार्ज':'Charge','डिलीवरी':'Delivery','निर्देश':'Instructions',
    'रिमार्क':'Remark','कैटेगरी':'Category','आइटम':'Item','मूल्य':'Rate','रेट':'Rate','विकल्प':'Options','चुनें':'Choose','स्टेटस':'Status','और':'and','या':'or',
    'लोकेशन':'Location','जगह':'Place','एरिया':'Area','पूरा पता':'Full Address','स्पेशल':'Special','सब':'All','सबसे':'Most','अच्छा':'Good','बढ़िया':'Great','शानदार':'Excellent',
    'साइन':'Sign','हस्ताक्षर':'Signature','अधिकृत':'Authorised','कंपनी':'Company','पता':'Address','संपर्क':'Contact','ईमेल':'Email','फोन':'Phone','सहायक':'Helper',
    'समस्या':'Problem','शिकायत':'Complaint','इमरजेंसी':'Emergency','खतरा':'Danger','मदद माँगें':'Request Help','भेजें':'Send','प्रतीक्षा':'Please Wait','लोड हो रहा':'Loading',
    'कृपया प्रतीक्षा करें':'Please Wait','सूचित करें':'Notify','चालू':'ON','बंद':'OFF','चालू है':'Running','बंद है':'Off','रेटिंग दें':'Rate Now','धन्यवाद!':'Thank You!'
  };
  var _keys=Object.keys(DICT).sort(function(a,b){ return b.length-a.length; });
  var _stored='hi';
  try{ _stored=localStorage.getItem('sw_uilang')||'hi'; }catch(e){}
  var _orig=new WeakMap();   /* node -> original text */
  var _trOn=false;

  function escRe(s){ return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }
  var _lbOk=true; try{ new RegExp('(?<=a)b'); }catch(e){ _lbOk=false; }
  function trText(txt){
    if(!txt) return txt;
    _keys.forEach(function(k){
      var kw=escRe(k);
      if(_lbOk){ var re=new RegExp('(?<![\\p{L}\\p{N}])'+kw+'(?![\\p{L}\\p{N}])','gu'); txt=txt.replace(re,function(){ return DICT[k]; }); }
      else { var re2=new RegExp('(^|[^\\p{L}\\p{N}])'+kw+'(?=$|[^\\p{L}\\p{N}])','gu'); txt=txt.replace(re2,function(a,b){ return b+DICT[k]; }); }
    });
    return txt;
  }
  function walk(root){
    if(!_trOn) return;
    try{
      var w=document.createTreeWalker(root||document.body, NodeFilter.SHOW_TEXT, null);
      var n, arr=[];
      while(w.nextNode()){ n=w.currentNode; arr.push(n); }
      arr.forEach(function(node){
        var p=node.parentNode; if(!p) return;
        var tag=p.nodeName;
        if(tag==='SCRIPT'||tag==='STYLE'||tag==='TEXTAREA'||tag==='INPUT'||tag==='SELECT'||tag==='NOSCRIPT'||tag==='CODE') return;
        var t=node.nodeValue||'';
        if(!t.trim()) return;
        var orig=_orig.get(node);
        if(orig===undefined) orig=t;
        var nt=trText(t);
        if(nt!==t){ _orig.set(node,orig); node.nodeValue=nt; }
      });
    }catch(e){}
  }
  /* observers: हर बदलते content पर दोबारा scan = full-app */
  var _mo=null,_tm=null;
  function watch(){
    if(_mo) return;
    _mo=new MutationObserver(function(){ if(_tm) clearTimeout(_tm); _tm=setTimeout(function(){ walk(document.body); },350); });
    try{ _mo.observe(document.body,{childList:true,subtree:true,characterData:true}); }catch(e){}
  }
  function dictOn(){
    _trOn=true; watch(); walk(document.body);
  }
  function dictOff(){
    _trOn=false;
    var all=document.querySelectorAll('body *');
    for(var i=0;i<all.length;i++){ var el=all[i]; for(var j=0;j<el.childNodes.length;j++){ var c=el.childNodes[j]; if(c.nodeType===3){ var o=_orig.get(c); if(o!==undefined){ c.nodeValue=o; } } } }
  }
  /* Google widget helpers (c46 had base) */
  function gHost(){
    var h=document.getElementById('swGtEl');
    if(!h){ h=document.createElement('div'); h.id='swGtEl'; h.style.cssText='position:absolute;top:-9999px;left:-9999px;width:8px;height:8px;overflow:hidden;opacity:.01;pointer-events:none;'; document.body.appendChild(h); }
    return h;
  }
  function gReady(){ try{ return !!(window.google&&google.translate&&gHost().querySelector('.goog-te-combo')); }catch(e){ return false; } }
  function gLoad(){
    try{
      if(document.querySelector('script[src*="translate_a/element.js"]')) return;
      window.swGtCb=function(){ try{ if(window.google&&google.translate){ new google.translate.TranslateElement({pageLanguage:'hi',autoDisplay:false,includedLanguages:'hi,en',layout:google.translate.TranslateElement.InlineLayout.SIMPLE},'swGtEl'); } }catch(e){} };
      var sc=document.createElement('script'); sc.src='https://translate.google.com/translate_a/element.js?cb=swGtCb'; document.head.appendChild(sc);
    }catch(e){}
  }
  function gApply(code){
    try{
      if(!gReady()){ gLoad(); return false; }
      var c=gHost().querySelector('.goog-te-combo');
      c.value=code; c.dispatchEvent(new Event('change',{bubbles:true}));
      return true;
    }catch(e){ return false; }
  }
  /* public apply: 'hi'=original, 'en'=dictionary + google, बाकी=google */
  window.uAppLang=function(code){
    try{ localStorage.setItem('sw_uilang',code); }catch(e){}
    _stored=code;
    dictOff();  /* ek baar me sirf ek language — पहले original restore */
    if(code==='hi'){ try{ gApply('hi'); }catch(e){} try{ showToast('🌐 Original (हिन्दी)'); }catch(e){} return; }
    if(code==='en'){ dictOn(); }
    var go=gApply(code);
    try{ if(go) showToast('🌐 पूरी App translate हो रही है...'); else showToast('🌐 English basic apply — internet पर पूरा होगा'); }catch(e){}
  };

  /* override c46 pickers */
var LGS=[['hi','हिन्दी'],['en','English']];
  window.swGtShow=function(){
    try{
      if(!document.querySelector('script[src*="translate_a/element.js"]')) gLoad();
      var o=document.getElementById('swGtOv');
      if(!o){ o=document.createElement('div'); o.id='swGtOv'; o.style.cssText='position:fixed;inset:0;z-index:9999992;display:none;align-items:center;justify-content:center;background:rgba(5,10,25,.55);padding:16px;'; document.body.appendChild(o); }
      o.innerHTML='<div style="max-width:430px;width:100%;background:#fff;border-radius:22px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.45);animation:ain46 .22s">'+
        '<div style="background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;padding:15px 16px;display:flex;justify-content:space-between;align-items:center;"><div><b style="font-size:15px;">🌐 पूरी App को भाषा में बदलें</b><br><span style="font-size:9.5px;opacity:.92;">Full-screen scan — A से Z तक सब translate</span></div><span style="font-size:22px;cursor:pointer;" onclick="swGtHide()">✕</span></div>'+
        '<div style="padding:12px 14px;max-height:62vh;overflow-y:auto;display:grid;grid-template-columns:repeat(2,1fr);gap:8px;">'+
          LGS.map(function(l){ return '<button type="button" onclick="swGtSet(\''+l[0]+'\')" style="padding:12px 8px;border-radius:11px;border:1.5px solid #e3ecfa;background:#f4f8ff;color:#0d3b66;font-weight:800;font-size:12.5px;cursor:pointer;">'+l[1]+'</button>'; }).join('')+
        '</div>'+
        '<div style="padding:9px 16px 13px;font-size:9.5px;color:#888;border-top:1px dashed #ddd;text-align:center;">English = offline scan भी + internet पर Google पूरा • data/cart reset नहीं</div>'+
      '</div>';
      o.style.display='flex';
      if(!_stored||_stored==='hi'){ try{ uAppLang('hi'); }catch(e){} }
    }catch(e){}
  };
  window.swGtHide=function(){ try{ var o=document.getElementById('swGtOv'); if(o) o.style.display='none'; }catch(e){} };
  window.swGtSet=function(code){ try{ uAppLang(code); swGtHide(); }catch(e){} };

  /* auto restore + scan on boot */
  if(_stored&&_stored!=='hi'){ if(_stored==='en') dictOn(); }
  setTimeout(function(){ try{ if(_stored==='en') dictOn(); }catch(e){} },1500);
  setInterval(function(){ try{ walk(document.body); }catch(e){} },6000);

  /* header translate chip highlight if en */
  /* ─────────────────────── 2) ORIGINAL COMPANY BILL ───────────────────────
     SewaAstra Steel Pvt Ltd — authorised sign + हर item/service photo सहित पूरी जानकारी */
  var CO={name:'SewaAstra Steel Pvt Ltd',tag:'Home Services • Steel • Appliances',gstin:'23ABCDE1234F1Z5',addr:'Shop 12, Service Road, Bhopal, Madhya Pradesh 462001',ph:'7869969190',city:'Bhopal'};
  function billLookup(items){
    var map={};
    FS.collection('app_config').doc('main').get().then(function(d){
      if(d.exists){ var x=d.data(); try{ var md=JSON.parse(x.mainData||'{}'); Object.keys(md).forEach(function(k){ (md[k]||[]).forEach(function(o){ if(o&&o.n){ map[o.n]={img:o.i||'',cat:k}; } }); }); }catch(e){} }
      renderBill(items,map);
    }).catch(function(){ renderBill(items,map); });
    return map;
  }
  function cImg(it,map){
    var m=map[(it.n||'')];
    var img=(it.i||(m&&m.img)||'');
    if(img) return '<img src="'+proEsc(img)+'" onerror="this.style.display=\'none\'" style="width:46px;height:46px;border-radius:9px;object-fit:cover;border:1px solid #eee;float:left;margin:0 10px 4px 0;">';
    return '';
  }
  function fmt(n){ return '₹'+(Number(n)||0).toLocaleString('en-IN'); }
  function renderBill(o,map){
    var cfg=(o._cfg)||{};
    var gstPct=Math.max(0,Number(cfg.gstPct)||0);
    var paid=!!(o.payment&&(o.payment.verified||/^paid/i.test(o.payment.status||'')));
    var isCash=/cash|cod|नकद/i.test(o.mode||'');
    var sub=Number(o.subtotal)||(o.items||[]).reduce(function(s,it){ return s+(Number(it.p)||0)*(it.qty||1); },0);
    var disc=Number(o.discount)||0;
    var base=Math.max(0,sub-disc);
    var gstAmt=Math.round(base*gstPct/100);
    var rowFn=function(it){
      var q=it.qty||1, line=(Number(it.p)||0)*q;
      return '<div style="display:flex;align-items:flex-start;border-bottom:1px dashed #e2e2e2;padding:9px 0;">'+cImg(it,map)+
        '<div style="flex:1;min-width:0;"><div style="font-weight:900;font-size:12.5px;color:#111;">'+proEsc(it.n)+'</div>'+
        (it.catName?'<div style="font-size:9.5px;color:#777;font-weight:700;">'+(it.selectedSub?('📦 '+proEsc(it.selectedSub)):(it.catName?'🛠️ '+proEsc(it.catName):''))+'</div>':'')+
        '<div style="font-size:10.5px;color:#444;">@ '+fmt(it.p)+(q>1?' × '+q:'')+'</div></div>'+
        '<div style="font-weight:900;font-size:12.5px;color:#111;">'+fmt(line)+'</div></div>';
    };
    var m=document.getElementById('proBillModal');
    if(!m){ document.body.insertAdjacentHTML('beforeend','<div id="proBillModal" onclick="if(event.target===this)proCloseBill()"><div class="pro-bill" id="proBillInner"></div></div>'); m=document.getElementById('proBillModal'); }
    var payB='';
    var payAct='';
    if(paid) payB='<div style="text-align:center;background:#e6f7ed;border:1px solid #a8e6c2;border-radius:12px;padding:10px;margin-top:10px;font-weight:900;color:#0f7a37;font-size:12.5px;">✅ PAID'+(o.payment&&o.payment.ref?('<br><span style="font-size:10px;">Ref: '+proEsc(o.payment.ref)+'</span>'):'')+'</div>';
    else {
      if(isCash) payB='<div style="text-align:center;background:#fff6e0;border:1px solid #ffd970;border-radius:12px;padding:10px;margin-top:10px;font-weight:900;color:#8a6100;font-size:12.5px;">💵 CASH (COD) — service के बाद partner को दें</div>';
      else { payB='<div style="text-align:center;background:#fff6e0;border:1px solid #ffd970;border-radius:12px;padding:10px;margin-top:10px;font-weight:900;color:#8a6100;font-size:12.5px;">⏳ PAYMENT DUE — नीचे से pay करें</div>';
        payAct='<div style="text-align:center;margin-top:10px;"><div style="font-size:12px;font-weight:900;color:#ff6b00;">📲 UPI/QR से भुगतान करें</div><div id="proQrBox" style="display:flex;justify-content:center;"></div><div style="font-size:11px;color:#888;">UPI ID: <b>'+proEsc(proUpiId())+'</b></div>'+
        '<a href="'+proUpiLink(o.total,o.id,'phonepe')+'" style="display:inline-block;margin:8px 4px 0;background:linear-gradient(90deg,#5f259f,#7b3fc4);color:#fff;padding:11px 18px;border-radius:12px;text-decoration:none;font-weight:900;font-size:12px;">💜 PhonePe ₹'+o.total+'</a>'+
        '<a href="'+proUpiLink(o.total,o.id)+'" style="display:inline-block;margin:8px 4px 0;background:linear-gradient(90deg,#15a04a,#1fc25e);color:#fff;padding:11px 18px;border-radius:12px;text-decoration:none;font-weight:900;font-size:12px;">📲 अन्य UPI</a></div>'; }
    }
    var rows=(o.items||[]).map(rowFn).join('')||'<div style="color:#999;">—</div>';
    var stamp='<div style="display:inline-block;border:2.5px solid #c62828;color:#c62828;border-radius:8px;padding:5px 12px;font-size:9.5px;font-weight:900;letter-spacing:1.5px;text-align:center;line-height:1.5;">✓ AUTHORISED<br>SEWAASTRA STEEL<br>PVT LTD</div>';
    document.getElementById('proBillInner').innerHTML=
      '<div style="background:linear-gradient(135deg,#10233f,#1b3a66);color:#fff;padding:16px 18px;border-radius:0;">'+
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;">'+
          '<div><div style="font-size:20px;font-weight:900;letter-spacing:.5px;">🛠️ '+proEsc(CO.name)+'</div>'+
          '<div style="font-size:9.5px;opacity:.9;font-weight:700;">'+proEsc(CO.tag)+'</div>'+
          '<div style="font-size:9px;opacity:.85;margin-top:5px;line-height:1.6;">'+proEsc(CO.addr)+'<br>☎ +91 '+proEsc(CO.ph)+'</div>'+
          '<div style="font-size:9.5px;margin-top:4px;color:#ffd970;font-weight:900;">GSTIN: '+proEsc(CO.gstin)+'</div></div>'+
          '<div style="text-align:right;font-size:9px;line-height:1.8;"><div style="border:1.5px solid #ffd970;border-radius:8px;padding:4px 10px;font-weight:900;color:#ffd970;font-size:10px;">TAX INVOICE</div>'+
          '<div style="margin-top:6px;color:#cfe1ff;">🆔 '+proEsc(o.id)+'</div></div>'+
        '</div>'+
      '</div>'+
      '<div style="padding:4px 16px 14px;background:#fff;color:#222;">'+
        '<div style="display:flex;justify-content:space-between;font-size:10.5px;color:#333;padding:9px 0;border-bottom:1px solid #eee;font-weight:700;">'+
          '<span>👤 Billed To: +91 '+proEsc(o.mobile||'—')+'</span><span>📅 '+proEsc(o.timestamp||((o.date||'')+' '+(o.time||'')))+'</span></div>'+
        (o.address?'<div style="font-size:10px;color:#666;padding:6px 0 2px;border-bottom:1px solid #eee;">📍 '+proEsc(o.address)+'</div>':'')+
        '<div style="margin-top:10px;">'+rows+'</div>'+
        '<div style="margin-top:6px;font-size:11.5px;">'+
          '<div style="display:flex;justify-content:space-between;padding:3px 0;"><span>Subtotal</span><b>'+fmt(sub)+'</b></div>'+
          (disc?'<div style="display:flex;justify-content:space-between;padding:3px 0;color:#15a04a;"><span>Discount (Coupon)</span><b>−'+fmt(disc)+'</b></div>':'')+
          (gstPct>0?'<div style="display:flex;justify-content:space-between;padding:3px 0;color:#7b1fa2;"><span>GST ('+gstPct+'%) <span style="font-size:9px;color:#999;">(included)</span></span><b>'+fmt(gstAmt)+'</b></div>':'')+
          '<div style="display:flex;justify-content:space-between;padding:3px 0;"><span>Visit / Service Charge</span><b>'+fmt(10)+'</b></div>'+
          '<div style="display:flex;justify-content:space-between;border-top:2px solid #111;margin-top:4px;padding:7px 0 2px;font-weight:900;font-size:14px;"><span>GRAND TOTAL</span><span>'+fmt(o.total)+'</span></div>'+
        '</div>'+payB+payAct+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;border-top:1px dashed #ccc;padding-top:10px;">'+
          '<div style="font-size:11px;color:#111;font-family:\'Segoe Script\',cursive;font-weight:900;">For '+proEsc(CO.name)+'</div>'+stamp+
        '</div>'+
        '<div style="text-align:right;margin-top:6px;font-size:11px;color:#111;font-weight:900;font-style:italic;">— Shoorshyam Vishwakarma<br><span style="font-size:9px;color:#666;font-style:normal;">Authorised Signatory</span></div>'+
        '<div style="text-align:center;font-size:9px;color:#999;margin-top:8px;border-top:1px dotted #ccc;padding-top:6px;">यह कंप्यूटर जनरेटेड बिल है — बिना हस्ताक्षर के भी मान्य। धन्यवाद 🙏</div>'+
        '<div style="display:flex;gap:8px;margin-top:12px;">'+
          '<button class="pro-bill-btn" style="background:#0d6efd;color:#fff;" onclick="proPrintBill(\''+o.id+'\')">🖨️ Print / PDF</button>'+
          '<button class="pro-bill-btn" style="background:#25d366;color:#fff;" onclick="proWABill(\''+o.id+'\')">📤 Share</button>'+
          '<button class="pro-bill-btn" style="background:#eee;color:#555;" onclick="proCloseBill()">✕ Close</button>'+
        '</div>'+
      '</div>';
    m.classList.add('open');
    try{ if(!paid&&!isCash&&typeof proMakeQR==='function'){ var qb=document.getElementById('proQrBox'); if(qb) proMakeQR(qb, proUpiLink(o.total,o.id)); } }catch(e){}
  }
  var _pB=window.proShowBill;
  window.proShowBill=function(oid,thenRate){
    window.__proBillRate = thenRate ? oid : null;
    var _pm=document.getElementById('proBillModal');
    if(!_pm){ document.body.insertAdjacentHTML('beforeend','<div id="proBillModal" onclick="if(event.target===this)proCloseBill()"><div class="pro-bill" id="proBillInner"></div></div>'); }

    var cfgP=FS.collection('config').doc('global').get().catch(function(){ return null; });
    var cfg2={};
    cfgP.then(function(d){ if(d&&d.exists) cfg2=d.data(); })
      .then(function(){ return FS.collection('orders').doc(oid).get(); })
      .then(function(d){
        if(!d.exists) return showAlert('त्रुटि','ऑर्डर नहीं मिला');
        var o=d.data(); o._cfg=cfg2; o._map={};
        var map={};
        FS.collection('app_config').doc('main').get().then(function(ad){
          if(ad.exists){ try{ var x=ad.data(); var md=JSON.parse(x.mainData||'{}'); Object.keys(md).forEach(function(k){ (md[k]||[]).forEach(function(s){ if(s&&s.n) map[s.n]={img:s.i||'',cat:k}; }); }); }catch(e){} }
          renderBill(o,map);
        }).catch(function(){ renderBill(o,map); });
      })
      .catch(function(e){ showAlert('त्रुटि',e.message); });
  };
  window.proWABill=function(oid){
    try{ FS.collection('orders').doc(oid).get().then(function(d){ if(!d.exists) return; var o=d.data(); var txt='🧾 *SewaAstra Steel Pvt Ltd — TAX INVOICE*%0A🆔 '+oid+'%0A'+(o.items||[]).map(function(i){ return '• '+i.n+(i.qty>1?' x'+i.qty:'')+' = ₹'+((Number(i.p)||0)*(i.qty||1)); }).join('%0A')+'%0A💰 Total: ₹'+o.total; window.open('https://wa.me/?text='+txt, '_blank', 'noopener,noreferrer'); }).catch(function(){}); }catch(e){}
  };
  /* print: clean A4 */
  window.proPrintBill=function(oid){
    try{
      FS.collection('orders').doc(oid).get().then(function(d){
        if(!d.exists) return; var o=d.data();
        var cfg2={}; FS.collection('config').doc('global').get().then(function(cd){ if(cd.exists) cfg2=cd.data(); }).catch(function(){}).then(function(){
          var sub=Number(o.subtotal)||0, disc=Number(o.discount)||0, gstPct=Math.max(0,Number(cfg2.gstPct)||0);
          var rows=(o.items||[]).map(function(it){ var q=it.qty||1; return '<tr><td style="padding:7px 4px;border-bottom:1px dashed #ccc;">'+(it.n||'')+(it.selectedSub?'<br><span style="color:#777;font-size:11px;">'+proEsc(it.selectedSub)+'</span>':'')+'</td><td style="text-align:center;">'+(it.qty||1)+'</td><td style="text-align:right;">₹'+((Number(it.p)||0))+'</td><td style="text-align:right;font-weight:bold;">₹'+(sub?((Number(it.p)||0)*q):0)+'</td></tr>'; }).join('');
          var w=window.open('', '_blank', 'noopener,noreferrer');
          w.document.write('<html><head><title>Invoice '+proEsc(oid)+'</title><style>body{font-family:Arial,sans-serif;color:#000;max-width:720px;margin:18px auto;padding:0 14px;font-size:12px;}h1{font-size:22px;margin:0}.head{display:flex;justify-content:space-between;border-bottom:3px double #000;padding-bottom:10px;}.muted{color:#555;font-size:10.5px;}table{width:100%;border-collapse:collapse;margin-top:10px;}th{background:#eee;text-align:left;padding:6px 4px;border-bottom:2px solid #000;}td{padding:6px 4px;border-bottom:1px solid #ccc;}.tot td{border-top:3px double #000;font-size:14px;font-weight:bold;}.sig{display:flex;justify-content:space-between;margin-top:34px;}button,a{display:none!important;}.stamp{border:2.5px solid #c62828;color:#c62828;border-radius:8px;padding:6px 12px;display:inline-block;font-size:10px;font-weight:bold;letter-spacing:1px;text-align:center;line-height:1.5;}</style></head><body>'+
          '<div class="head"><div><h1>🛠️ SewaAstra Steel Pvt Ltd</h1><div class="muted">'+proEsc(CO.tag)+'<br>'+proEsc(CO.addr)+' • ☎ +91 '+CO.ph+'</div><div class="muted"><b>GSTIN: '+proEsc(CO.gstin)+'</b></div></div><div style="text-align:right;"><b style="font-size:16px;">TAX INVOICE</b><br>🆔 '+proEsc(oid)+'<br>'+proEsc(o.timestamp||'')+'</div></div>'+
          '<div class="muted" style="margin-top:8px;">👤 Billed To: +91 '+proEsc(o.mobile||'')+(o.address?' &nbsp;•&nbsp; 📍 '+proEsc(o.address):'')+'</div>'+
          '<table><tr><th>Item / Service</th><th style="width:46px;">Qty</th><th style="width:80px;">Rate</th><th style="width:100px;">Amount</th></tr>'+rows+
          '<tr><td colspan="3" style="text-align:right;"><b>Subtotal</b></td><td style="text-align:right;"><b>₹'+sub+'</b></td></tr>'+(disc?'<tr><td colspan="3" style="text-align:right;color:green;"><b>Discount</b></td><td style="text-align:right;color:green;"><b>−₹'+disc+'</b></td></tr>':'')+(gstPct>0?'<tr><td colspan="3" style="text-align:right;">GST ('+gstPct+'%) (included)</td><td style="text-align:right;">₹'+Math.round((sub-disc)*gstPct/100)+'</td></tr>':'')+
          '<tr class="tot"><td colspan="3" style="text-align:right;">GRAND TOTAL</td><td style="text-align:right;">₹'+o.total+'</td></tr></table>'+
          '<div class="muted" style="margin-top:6px;">Payment: '+proEsc(o.mode||'—')+(o.payment&&o.payment.ref?(' • Ref/UTR: '+proEsc(o.payment.ref)):'')+'</div>'+
          '<div class="sig"><div><b>For SewaAstra Steel Pvt Ltd</b><div class="stamp" style="margin-top:12px;">✓ AUTHORISED<br>SEWAASTRA STEEL<br>PVT LTD</div></div>'+
          '<div style="text-align:right;"><div style="margin-top:40px;border-top:1px solid #000;padding-top:4px;width:210px;font-weight:bold;font-style:italic;">Shoorshyam Vishwakarma<br><span style="font-size:10px;font-weight:normal;">Authorised Signatory</span></div></div></div>'+
          '<p class="muted" style="text-align:center;margin-top:18px;">यह कंप्यूटर जनरेटेड बिल है। धन्यवाद 🙏</p>'+
          '</body></html>');
          w.document.close();
          setTimeout(function(){ try{ w.print(); }catch(e){} },700);
        });
      }).catch(function(){});
    }catch(e){}
  };
  /* completion पर पुराना rate-flow: bill के बाद rating */
  try{ if(window.proStartRatingWatcher){} }catch(e){}

  /* History/tracking में 🧾 Bill button inject */
  function billScan(){
    try{
      var els=document.querySelectorAll('[onclick*="openLiveTracking(\'"],[onclick*="openRateModal(\'"],[onclick*="openOrderChat(\'"]');
      for(var i=0;i<els.length;i++){
        var el=els[i];
        var mt=(el.getAttribute('onclick')||'').match(/'([^']+)'/); if(!mt) continue;
        var oid=mt[1];
        var host=el.parentElement; if(!host) continue;
        if(host.querySelector('[data-cbill="'+oid+'"]')) continue;
        var b=document.createElement('button');
        b.setAttribute('data-cbill',oid);
        b.style.cssText='flex:1;min-width:88px;background:#0d47a1;color:#fff;border:none;padding:8px;border-radius:8px;font-size:11px;font-weight:bold;cursor:pointer;';
        b.innerHTML='🧾 Bill';
        b.onclick=function(){ try{ proShowBill(oid); }catch(e){} };
        host.appendChild(b);
      }
    }catch(e){}
  }
  setInterval(billScan,4000);

  /* ─────────────────────── 3) SOS CLOSE को सुंदर बनाओ ─────────────────────── */
  var st=document.createElement('style'); st.id='c47Sos';
  st.textContent=
    '.sosX{width:34px!important;height:34px!important;background:rgba(255,255,255,.28)!important;border:1.5px solid rgba(255,255,255,.55)!important;color:#fff!important;border-radius:50%!important;font-size:15px!important;display:flex!important;align-items:center!important;justify-content:center!important;transition:.2s!important}'+
    '.sosX:hover{background:rgba(255,255,255,.5)!important;transform:rotate(90deg)}'+
    '.sosCls{width:auto!important;margin:8px auto 0!important;display:block!important;background:linear-gradient(135deg,#4a1a1a,#7f2d2d)!important;color:#ffd9d9!important;border:1.5px solid #a33!important;border-radius:30px!important;padding:11px 26px!important;font-weight:900!important;font-size:12.5px!important;box-shadow:0 6px 16px rgba(0,0,0,.35)!important}'+
    '.sosCls:hover{background:linear-gradient(135deg,#5c2020,#8f3434)!important}'+
    '.a36head .x36{border-radius:50%!important;background:rgba(255,255,255,.2)!important;border:1.5px solid rgba(255,255,255,.5)!important;width:36px!important;height:36px!important;display:flex!important;align-items:center!important;justify-content:center!important;font-size:16px!important;cursor:pointer!important;color:#fff!important}';
  document.head.appendChild(st);

  console.log('%c 🌐🧾🆘 CUSTOMER v4.7 — REAL TRANSLATE + ORIGINAL BILL + SOS CLOSE ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 29 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([29, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 30 ═══ */
try {
/* ═══════════════ CUSTOMER v4.8 — LANGUAGE 1-at-a-time + PROFILE-only + DELETE BOX ═══════════════ */
(function(){
  if(window.__c48) return; window.__c48=1;

  /* 1) TOP (header) वाला 🌐 हटाओ — language अब सिर्फ Profile → Settings में */
  try{ var hd=document.getElementById('hdGt'); if(hd&&hd.parentNode) hd.parentNode.removeChild(hd); }catch(e){}

  /* 2) Language: एक बार में सिर्फ एक — पहले original (hi) पर लौटो, फिर नई भाषा लगाओ */
  window.swGtSet=function(code){
    var t=code||'hi';
    if(t!=='hi'){ try{ if(window.uAppLang) window.uAppLang('hi'); }catch(e){} }
    setTimeout(function(){
      try{ if(window.uAppLang) window.uAppLang(t); }catch(e){}
      try{ if(window.swGtHide) window.swGtHide(); }catch(e){}
    }, t==='hi'?50:340);
  };
  /* boot par sirf saved वाली ek language (अगर hi नहीं) */
  try{
    var saved=localStorage.getItem('sw_uilang')||'hi';
    if(saved!=='hi') setTimeout(function(){ try{ if(window.uAppLang) window.uAppLang(saved); }catch(e){} },1600);
  }catch(e){}

  /* 3) History DELETE / CANCEL — सुंदर box history के ऊपर (popup), नीचे cancel पर बस बंद */
  var cs=document.createElement('style'); cs.id='c48st'; cs.textContent=
    '#cCOv{background:rgba(12,8,2,.42)!important;backdrop-filter:blur(5px)!important;align-items:flex-start!important;padding:12vh 16px 16px!important;z-index:9999998!important}'+
    '#cCOv.on{display:flex}'+
    '#cCOv .ccard{max-width:380px!important;width:100%!important;border-radius:24px!important;border:1px solid rgba(255,255,255,.22)!important;box-shadow:0 30px 80px rgba(0,0,0,.5)!important;animation:c48in .26s cubic-bezier(.2,1.2,.35,1)!important;overflow:hidden!important}'+
    '@keyframes c48in{from{transform:scale(.92) translateY(16px);opacity:0}to{transform:none;opacity:1}}'+
    '#cCOv .cch{background:linear-gradient(135deg,#7a2a14,#c0392b)!important;padding:20px 16px 14px!important}'+
    '#cCOv .ccb{padding:4px 18px 20px!important}'+
    '#cCOv .rwc{display:flex!important;gap:9px!important;margin-top:15px!important}'+
    '#cCOv .rwc button{flex:1!important;border:none!important;border-radius:13px!important;padding:13px!important;font-weight:900!important;font-size:12.5px!important;cursor:pointer!important}'+
    '#cCYes{background:linear-gradient(135deg,#d32f2f,#ff6b5a)!important;color:#fff!important}'+
    '#cCOv .yes:not(.danger){background:linear-gradient(135deg,#0d6efd,#4d9bff)!important;color:#fff!important}'+
    '#cCNo{background:#f1f3f5!important;color:#4a4f5a!important}'+
    'body.dark-mode #cCNo{background:#262b36!important;color:#ccd3e0!important}'+
    '#cCOv .ccmsg{font-size:12.5px!important;line-height:1.75!important;color:#333!important;font-weight:600!important}'+
    'body.dark-mode #cCOv .ccmsg{color:#dfe4ee!important}'+
    'body.dark-mode #cCOv .ccard{background:#1e2330!important}'+
    'body.dark-mode #cCOv .cch{background:linear-gradient(135deg,#7a2a14,#b03a2b)!important}';
  document.head.appendChild(cs);

  /* agar kisi jagah native confirm बचा हो तो उसे भी सुंदर box से रोकें (delete/cancel path) */
  try{
    window.c48cf=function(oid,kind){
      if(!window.cConfirm) return false;
      var msg,ic,tt;
      if(kind==='del'){ msg='ऑर्डर '+oid+' को history से हमेशा के लिए delete करना है?'; ic='🗑️'; tt='Delete Order'; }
      else { msg='ऑर्डर '+oid+' रद्द करना है?\n\nक्या आपको पक्का यह order cancel करना है?'; ic='❌'; tt='Cancel Order'; }
      window.cConfirm(msg,{ic:ic,title:tt,ok:kind==='del'?'हाँ, delete करें':'हाँ, रद्द करें',danger:true}).then(function(ok){
        if(!ok) return;
        var p=FS.collection('orders').doc(oid);
        if(kind==='del'){ p.delete().then(done).catch(er); }
        else { p.update({status:'Cancelled',cancelledBy:'customer',cancelledAt:Date.now()}).then(done).catch(er); }
        function done(){ try{ showToast(kind==='del'?'🗑️ ऑर्डर delete हो गया':'❌ ऑर्डर रद्द हो गया'); }catch(e){} try{ closeCustomAlert(); }catch(e){} setTimeout(function(){ try{ window.showHistory&&window.showHistory(); }catch(e){} },350); }
        function er(e){ try{ showAlert('त्रुटि', e.message); }catch(x){} }
      });
      return true;
    };
  }catch(e){}
  console.log('%c 🌐🗑️ CUSTOMER v4.8 — LANG 1× + DELETE BOX ✅ ','background:#6a1b9a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 30 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([30, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 31 ═══ */
try {
/* ═══════════════ CUSTOMER v4.9 — 🏙️ CITY CHANGE OPTION (Profile) ═══════════════ */
(function(){
  if(window.__c49) return; window.__c49=1;
  var CITIES=['Bhopal','Indore','Gwalior','Jabalpur','Ujjain','Sagar','Dewas','Ratlam','Rewa','Satna','Guna','Hoshangabad','अन्य'];
  function cCity(){ try{ return localStorage.getItem('sw_city')||'Bhopal'; }catch(e){ return 'Bhopal'; } }
  function cId(m){ try{ var s=(localStorage.getItem('sw_user')||'').trim(); if(/^\d{10}$/.test(s)) return s; if(s.indexOf('@')>-1) return s; var u=firebase.auth().currentUser; if(u) return u.uid; if(s) return s; }catch(e){} return ''; }
  window.cSetCity=function(nm){
    try{ localStorage.setItem('sw_city',nm); }catch(e){}
    var l=document.getElementById('c49Lbl'); if(l) l.innerHTML='🏙️ मेरा शहर (Service): <b style="color:var(--primary);">'+nm+'</b>';
    var k=cId();
    if(k) FS.collection('users').doc(k).set({city:nm,cityAt:Date.now()},{merge:true}).catch(function(){});
    try{ if(window.showToast) showToast('✅ शहर बदला: '+nm); else if(window.cShowToast) cShowToast('✅ शहर बदला: '+nm); }catch(e){}
    try{ var o=document.getElementById('c49Ov'); if(o) o.style.display='none'; }catch(e){}
  };
  window.cCityShow=function(){
    var o=document.getElementById('c49Ov');
    if(!o){ o=document.createElement('div'); o.id='c49Ov'; o.style.cssText='position:fixed;inset:0;z-index:9999996;display:none;align-items:center;justify-content:center;background:rgba(5,10,25,.55);padding:16px;'; document.body.appendChild(o); }
    var cur=cCity();
    o.innerHTML='<div style="max-width:430px;width:100%;background:#fff;border-radius:22px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.45);">'+
      '<div style="background:linear-gradient(135deg,#0d47a1,#1976d2);color:#fff;padding:15px 16px;display:flex;justify-content:space-between;align-items:center;"><div><b style="font-size:15px;">🏙️ अपना शहर चुनें</b><br><span style="font-size:9.5px;opacity:.92;">SewaAstra सेवा किस शहर में चाहिए</span></div><span style="font-size:22px;cursor:pointer;" onclick="c49Hide()">✕</span></div>'+
      '<div style="padding:12px 14px;max-height:58vh;overflow-y:auto;display:grid;grid-template-columns:repeat(2,1fr);gap:8px;">'+
        CITIES.map(function(c){ return '<button type="button" onclick="cSetCity(\''+c+'\')" style="padding:12px 8px;border-radius:11px;border:1.5px solid '+(c===cur?'var(--primary)':'#e3ecfa')+';background:'+(c===cur?'var(--primary-light)':'#f4f8ff')+';color:#0d3b66;font-weight:800;font-size:12.5px;cursor:pointer;">'+c+(c===cur?' ✓':'')+'</button>'; }).join('')+'</div>'+
      '<div style="padding:10px 16px 13px;font-size:9.5px;color:#888;border-top:1px dashed #ddd;text-align:center;">आपका चुना शहर आपके profile में save रहता है — नए booking पर सेवा वहीं आधारित दिखेगी।</div></div>';
    o.style.display='flex';
  };
  window.c49Hide=function(){ try{ var o=document.getElementById('c49Ov'); if(o) o.style.display='none'; }catch(e){} };
  /* Profile sheet में row डालो (GPS row के ठीक ऊपर) */
  function row(){
    try{
      var gps=document.querySelector('[onclick^="getLiveLocation"]');
      var ref=gps||document.querySelector('.setting-item-row');
      if(!ref||document.getElementById('c49Row')) return;
      var d=document.createElement('div');
      d.id='c49Row';
      d.className='setting-item-row';
      d.style.cssText='cursor:pointer;border-color:var(--primary);background:var(--primary-light);';
      d.setAttribute('onclick','cCityShow()');
      d.innerHTML='<div id="c49Lbl" style="color:var(--primary);"><i class="fa fa-city"></i> 🏙️ मेरा शहर (Service): <b>'+cCity()+'</b></div> <i class="fa fa-chevron-right" style="font-size:12px;color:var(--primary);"></i>';
      if(ref&&ref.parentNode) ref.parentNode.insertBefore(d,ref);
      /* saved city को users doc में भी sync (login हो तो) */
      var k=cId(); if(k){ FS.collection('users').doc(k).set({city:cCity()},{merge:true}).catch(function(){}); }
    }catch(e){}
  }
  try{ row(); }catch(e){}
  setTimeout(row,1500);
  setTimeout(row,4500);
  console.log('%c 🏙️ CUSTOMER v4.9 — CITY CHANGE ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 31 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([31, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 32 ═══ */
try {
/* ═══════════════ CUSTOMER v5.0 — 🛒 CART REFRESH-SAFE (localStorage) — refresh par data reset नहीं ═══════════════ */
(function(){
  if(window.__c50) return; window.__c50=1;
  var KEY='sw_cart_v2';
  function nowCart(){ try{ if(typeof cart==='undefined') return []; return cart||[]; }catch(e){ return []; } }
  window.cartSave=function(){ try{ localStorage.setItem(KEY, JSON.stringify(nowCart())); }catch(e){} };
  window.cartRestore=function(){
    try{
      var cur=nowCart();
      if(cur&&cur.length) return;                 /* पहले से कुछ है — मत छेड़ो */
      var raw=localStorage.getItem(KEY); if(!raw) return;
      var s=JSON.parse(raw);
      if(s&&s.length){
        /* same top-level binding में restore — cart global lexical env है */
        cart=s.slice();
        try{ var b=document.getElementById('bCount'); if(b) b.innerText=String(cart.length); }catch(e){}
        try{ if(typeof renderCart==='function') renderCart(); else if(typeof openCart==='function'){} }catch(e){}
      }
    }catch(e){}
  };
  /* हर 1.2s cart save → refresh के बाद भी वापस */
  setInterval(window.cartSave,1200);
  window.addEventListener('pagehide',window.cartSave);
  window.addEventListener('beforeunload',window.cartSave);
  setTimeout(window.cartRestore,300);
  setTimeout(window.cartRestore,1400);
  setTimeout(window.cartRestore,4000);
  console.log('%c 🛒 CUSTOMER v5.0 — CART REFRESH-SAFE ✅ ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 32 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([32, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 33 ═══ */
try {
(function(){
  if(window.__swEmailAuth7) return; window.__swEmailAuth7=1;
  var mode='in';
  function msgEl(){ return document.getElementById('paAuthMsg'); }
  function setMsg(t){ var m=msgEl(); if(m){ if(t){ m.style.display='block'; m.innerHTML=t; } else m.style.display='none'; } }
  function validEmail(v){ return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v); }
  function label(){
    var b=document.getElementById('emailPassBtn'), l=document.getElementById('emailModeLink');
    if(b) b.innerHTML = mode==='up' ? '📝 अकाउंट बनाएं &nbsp;<i class="fa fa-user-plus"></i>' : '🔐 Login करें &nbsp;<i class="fa fa-arrow-right"></i>';
    if(l) l.innerHTML = mode==='up' ? '← पहले से अकाउंट है? Login करें' : 'पहली बार? नया अकाउंट बनाएं →';
  }
  window.emailModeToggle=function(){ mode=(mode==='in')?'up':'in'; label(); setMsg(''); };
  window.emailPassReset=function(){
    var e=(document.getElementById('userEmail').value||'').trim();
    if(!validEmail(e)) return setMsg('⚠️ पहले अपना सही ईमेल पता लिखें');
    showLoader('Reset link भेजा जा रहा है...');
    firebase.auth().sendPasswordResetEmail(e).then(function(){
      hideLoader(); setMsg('');
      showAlert('पासवर्ड रीसेट ✉️','अगर यह ईमेल registered है तो रीसेट link भेज दिया गया है।<br><b>Spam/Junk</b> folder भी check करें — मेल के link से नया पासवर्ड बनाकर login करें।');
    }).catch(function(err){ hideLoader(); setMsg(proAuthErr(err)); });
  };
  function done(user,isNew){
    var em=String(user.email||'').trim().toLowerCase();
    localStorage.setItem('sw_logged','true');
    localStorage.setItem('sw_user', em);
    try{ checkAdminAccess(em); }catch(e){}
    var ao=document.getElementById('authOverlay'); if(ao) ao.style.display='none';
    var pp=document.getElementById('profilePhoneDisplay'); if(pp) pp.innerText=em;
    try{ if(window.fetchCityNameByGPS) fetchCityNameByGPS(); }catch(e){}
    try{ if(window.checkAndShowInstallModalAfterLogin) checkAndShowInstallModalAfterLogin(); }catch(e){}
    showToast(isNew?'अकाउंट बन गया — स्वागत है! 🎉':'लॉगिन सफल — स्वागत है! 👋');
    setTimeout(function(){ try{ if(window.startMyOrdersListener) startMyOrdersListener(); }catch(e){} },600);
    setTimeout(function(){ try{ if(window.proSaveProfile) proSaveProfile(); }catch(e){} },1400);
    try{ document.getElementById('userPass').value=''; }catch(e){}
  }
  function fail(err){
    hideLoader(); var c=(err&&err.code)||'';
    if(c==='auth/email-already-in-use') setMsg('इस ईमेल से पहले account मौजूद है — सही पासवर्ड डालकर Login करें, या Google से login करें।');
    else if(c==='auth/user-not-found') setMsg('यह ईमेल registered नहीं है — नीचे "नया अकाउंट बनाएं" से signup करें।');
    else if(c==='auth/wrong-password'||c==='auth/invalid-credential') setMsg('❌ पासवर्ड गलत है — "पासवर्ड भूल गए?" से रीसेट करें।');
    else if(c==='auth/too-many-requests') setMsg('⏳ बहुत कोशिशें — कुछ देर बाद फिर try करें।');
    else if(c==='auth/invalid-email') setMsg('⚠️ ईमेल पता सही नहीं है।');
    else setMsg(proAuthErr(err));
  }
  function autoUp(){
    mode='up'; label();
    setMsg('नया ईमेल — अभी आपका account बना दिया जाएगा (यही ईमेल+पासवर्ड से आगे login होगा)।');
  }
  window.emailPassSubmit=function(){
    var e=(document.getElementById('userEmail').value||'').trim();
    var p=document.getElementById('userPass').value||'';
    if(!validEmail(e)) return setMsg('⚠️ सही ईमेल पता लिखें (example@mail.com)');
    if(p.length<6) return setMsg('⚠️ पासवर्ड कम से कम 6 अक्षर का होना चाहिए');
    setMsg('');
    showLoader(mode==='up'?'अकाउंट बनाया जा रहा है...':'लॉगिन हो रहा है...');
    if(mode==='up'){
      firebase.auth().createUserWithEmailAndPassword(e,p).then(function(r){ hideLoader(); done(r.user,true); })
        .catch(function(err){ if(err&&err.code==='auth/email-already-in-use'){
          firebase.auth().signInWithEmailAndPassword(e,p).then(function(r){ hideLoader(); done(r.user,false); }).catch(fail);
        } else fail(err); });
    } else {
      firebase.auth().signInWithEmailAndPassword(e,p).then(function(r){ hideLoader(); done(r.user,false); })
        .catch(function(err){
          if(err&&err.code==='auth/user-not-found'){
            autoUp();
            firebase.auth().createUserWithEmailAndPassword(e,p).then(function(r){ hideLoader(); done(r.user,true); }).catch(fail);
          } else fail(err);
        });
    }
  };
  /* 📵 mobile OTP entry points बंद — किसी पुराने button ने call किया तो नरम message */
  var noOTP=function(){ showToast('📵 मोबाइल OTP login बंद — अब ईमेल+पासवर्ड (या Google) से login करें ✉️'); };
  window.sendRealPhoneOTP=noOTP; window.verifyRealPhoneOTP=noOTP; window.resetAuth=noOTP;
  console.log('%c ✉️ EMAIL+PASSWORD LOGIN v7.0 (mobile OTP removed) ','background:#0d47a1;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 33 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([33, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 34 ═══ */
try {
/* ═══ SewaAstra v9 — KHUD KI Masked Calling (WebRTC voice, number kabhi nahi dikhta) ═══ */
(function(){
if(window.__swCall9) return; window.__swCall9=1;
var ROLE='cust';
var PEER=(ROLE==='cust')?'Service Partner':'Customer';
function esc(s){ s=String(s==null?'':s); return s.replace(/[&<>"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];}); }
function nt(m){ try{ if(window.showToast){ window.showToast(m); return; } }catch(e){} try{ if(window.toast){ window.toast(m); return; } }catch(e){} }
function vib(p){ try{ if(navigator.vibrate) navigator.vibrate(p); }catch(e){} }
function myUid(){ try{ var u=firebase.auth().currentUser; return u?(u.uid||''):''; }catch(e){ return ''; } }
function myPhone(){ try{ var k=(ROLE==='cust')?'sw_user':'swp_phone'; return String(localStorage.getItem(k)||'').replace(/\D/g,'').slice(-10); }catch(e){ return ''; } }
function myKey(){ return myUid()||myPhone()||ROLE; }
/* audio */
var AC=null;
function ac(){ try{ if(!AC){ var C=window.AudioContext||window.webkitAudioContext; if(C) AC=new C(); } if(AC&&AC.state==='suspended'){ AC.resume().catch(function(){}); } return AC; }catch(e){ return null; } }
function tone(f,dl,dur,vol){ try{ var c=ac(); if(!c) return; var o=c.createOscillator(),g=c.createGain(); o.connect(g); g.connect(c.destination); o.type='sine'; o.frequency.value=f; var t=c.currentTime+dl; g.gain.setValueAtTime(0.0001,t); g.gain.exponentialRampToValueAtTime(vol||0.25,t+0.04); g.gain.exponentialRampToValueAtTime(0.0001,t+dur); o.start(t); o.stop(t+dur+0.05); }catch(e){} }
var ringT=null,vibT=null;
function ringStart(incoming){ ringStop(); ringT=setInterval(function(){ tone(440,0,0.32,0.3); tone(480,0.38,0.32,0.3); if(!incoming){ tone(660,0.82,0.16,0.2); } },1400); vibT=setInterval(function(){ vib([420,150,420,150,420]); },1750); tone(440,0,0.32,0.3); tone(480,0.38,0.32,0.3); vib([420,150,420]); }
function ringStop(){ if(ringT){ clearInterval(ringT); ringT=null; } if(vibT){ clearInterval(vibT); vibT=null; } try{ if(navigator.vibrate) navigator.vibrate(0); }catch(e){} }
/* state */
var pc=null,localS=null,remoteA=null,st={s:'idle',oid:''},docUn=null,candUn=null,seenC={},waitT=null,secT=null,secs=0,muted=false,bigSpk=true,remReady=false,pendC=[];
function callDoc(oid){ return FS.collection('orders').doc(oid).collection('swcall').doc('live'); }
function callCands(oid){ return FS.collection('orders').doc(oid).collection('swcall').doc('live').collection('cands'); }
function rtcConf(){ return {iceServers:[{urls:['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302']},{urls:'turn:openrelay.metered.ca:80',username:'openrelayproject',credential:'openrelayproject'},{urls:'turn:openrelay.metered.ca:443',username:'openrelayproject',credential:'openrelayproject'},{urls:'turns:openrelay.metered.ca:443?transport=tcp',username:'openrelayproject',credential:'openrelayproject'}], iceCandidatePoolSize:8}; }
/* ---- FULL SCREEN UI ---- */
function ensureUI(){
if(document.getElementById('swCallFS')){ remoteA=document.getElementById('swCallRemote'); return; }
var stl=document.createElement('style'); stl.id='swc9st';
stl.textContent='.swcAv{width:110px;height:110px;border-radius:50%;margin:0 auto;display:flex;align-items:center;justify-content:center;font-size:52px;background:linear-gradient(135deg,#ff6b00,#ff2d95 55%,#7a2bff);box-shadow:0 0 0 8px rgba(255,255,255,.12),0 14px 44px rgba(255,45,149,.5);animation:swcPulse 1.5s ease-in-out infinite;}@keyframes swcPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.09)}}.swcB{border:none;border-radius:16px;padding:15px 8px;font-weight:900;font-size:13.5px;cursor:pointer;color:#fff;flex:1;}.swcB:active{transform:scale(.95);}';
document.head.appendChild(stl);
var d=document.createElement('div'); d.id='swCallFS';
d.style.cssText='position:fixed;inset:0;z-index:2147483645;display:none;align-items:center;justify-content:center;padding:20px;background:radial-gradient(circle at 50% 20%,#26364f 0%,#0b1220 55%,#050914 100%);color:#fff;font-family:system-ui,Arial,sans-serif;';
d.innerHTML='<audio id="swCallRemote" autoplay playsinline style="display:none;"></audio><div id="swCallInner" style="width:100%;max-width:360px;text-align:center;"></div>';
document.body.appendChild(d); remoteA=document.getElementById('swCallRemote');
}
function fsShow(){ ensureUI(); document.getElementById('swCallFS').style.display='flex'; }
function fsHide(){ var e=document.getElementById('swCallFS'); if(e) e.style.display='none'; }
function paint(h){ ensureUI(); document.getElementById('swCallInner').innerHTML=h; fsShow(); }
function bind(id,fn){ var b=document.getElementById(id); if(b) b.onclick=function(){ try{ fn(); }catch(e){} }; }
function head(emoji,title,oid,sub){ return '<div class="swcAv">'+emoji+'</div><div style="font-size:19px;font-weight:900;margin-top:14px;">'+title+'</div><div style="font-size:12px;opacity:.85;margin-top:6px;line-height:1.7;">📦 '+esc(oid)+'<br>'+sub+'</div>'; }
function paintOut(oid){ paint(head('🔒','🔒 Masked Call',oid,PEER+' से जुड़ रहे हैं…<br>दोनों का असली नंबर <b>छिपा है</b> 🙈')+'<div style="font-size:12.5px;font-weight:800;color:#ffd970;margin-top:12px;">📞 Ring बज रही है… रुकें</div><div style="display:flex;gap:10px;margin-top:20px;"><button class="swcB" id="swcEnd" style="background:linear-gradient(135deg,#e53935,#ff6659);">📵 काटें</button></div><div style="font-size:10px;opacity:.6;margin-top:12px;">🎙️ Mic ON रखें • SewaAstra Secure Voice (अपनी तकनीक, कोई Agora नहीं)</div>'); bind('swcEnd',function(){ endCall('कॉल रद्द',''); }); }
function paintIn(oid){ paint(head('📞','Incoming Masked Call',oid,'कॉलर का असली नंबर <b>छिपा है</b><br>(SewaAstra Secure Voice) 🔊📳')+'<div style="display:flex;gap:10px;margin-top:22px;"><button class="swcB" id="swcDec" style="background:#374151;">✖ काटें</button><button class="swcB" id="swcAns" style="background:linear-gradient(135deg,#15a04a,#1fc25e);box-shadow:0 8px 24px rgba(21,160,74,.5);">✅ उठाएँ</button></div>'); bind('swcAns',function(){ vib(40); answerCall(oid); }); bind('swcDec',function(){ declineCall(oid); }); }
function paintLive(oid){ paint(head('🟢','🔒 Masked Call • LIVE',oid,PEER+' जुड़ा है • नंबर छिपा है 🙈')+'<div id="swcT" style="font-size:26px;font-weight:900;color:#7dffa0;margin-top:10px;">00:00</div><div style="display:flex;gap:10px;margin-top:18px;"><button class="swcB" id="swcM" style="background:#374151;">🔇 Mute</button><button class="swcB" id="swcS" style="background:#0d6efd;">🔊 Speaker:ON</button></div><div style="display:flex;gap:10px;margin-top:10px;"><button class="swcB" id="swcE" style="background:linear-gradient(135deg,#e53935,#ff6659);padding:16px 8px;font-size:15px;">📵 End</button></div>'); bind('swcE',function(){ endCall('कॉल समाप्त',''); }); bind('swcM',function(){ muted=!muted; try{ if(localS) localS.getAudioTracks().forEach(function(t){ t.enabled=!muted; }); }catch(e){} var b=document.getElementById('swcM'); if(b) b.innerHTML=muted?'🔇 Muted':'🔇 Mute'; }); bind('swcS',function(){ bigSpk=!bigSpk; try{ if(remoteA) remoteA.volume=bigSpk?1:0.35; }catch(e){} var b=document.getElementById('swcS'); if(b) b.innerHTML=bigSpk?'🔊 Speaker:ON':'🔈 Speaker:LOW'; }); }
function paintEnd(t,s){ paint('<div style="font-size:54px;">📵</div><div style="font-size:16px;font-weight:900;margin-top:12px;">'+esc(t||'कॉल समाप्त')+'</div>'+(s?'<div style="font-size:11.5px;opacity:.75;margin-top:6px;">'+esc(s)+'</div>':'')); }
/* ---- peer helpers ---- */
function closePc(){ try{ if(pc) pc.close(); }catch(e){} pc=null; }
function stopMic(){ try{ if(localS) localS.getTracks().forEach(function(t){ t.stop(); }); }catch(e){} localS=null; }
function unsubs(){ try{ if(docUn) docUn(); }catch(e){} docUn=null; try{ if(candUn) candUn(); }catch(e){} candUn=null; }
function stopTimer(){ if(secT){ clearInterval(secT); secT=null; } if(waitT){ clearTimeout(waitT); waitT=null; } }
function startTimer(){ stopTimer2(); secs=0; secT=setInterval(function(){ secs++; var m=Math.floor(secs/60),s=secs%60; var e=document.getElementById('swcT'); if(e) e.innerText=(m<10?'0':'')+m+':'+(s<10?'0':'')+s; },1000); }
function stopTimer2(){ if(secT){ clearInterval(secT); secT=null; } }
function mkPc(oid){
closePc(); var P=null;
try{ P=new RTCPeerConnection(rtcConf()); }catch(e){ return null; }
pc=P;
P.ontrack=function(ev){ try{ remoteA.srcObject=ev.streams[0]; try{ remoteA.muted=false; remoteA.volume=1; }catch(e){} var pr=remoteA.play(); if(pr&&pr.catch) pr.catch(function(){}); }catch(e){} };
P.onicecandidate=function(ev){ if(ev.candidate){ try{ callCands(oid).add({from:myKey(),role:ROLE,cand:JSON.stringify(ev.candidate),ts:Date.now()}).catch(function(){}); }catch(e){} } };
return P;
}
function flushC(){ try{ if(!pc||!pc.remoteDescription) return; var q=pendC; pendC=[]; q.forEach(function(c){ try{ pc.addIceCandidate(c).catch(function(){}); }catch(e){} }); }catch(e){} }
function listenCands(oid){ try{ if(candUn) candUn(); }catch(e){} try{ candUn=callCands(oid).onSnapshot(function(sn){ sn.docChanges().forEach(function(ch){ if(ch.type!=='added') return; if(seenC[ch.doc.id]) return; var m=ch.doc.data()||{}; if(m.from===myKey()) return; seenC[ch.doc.id]=1; if(!pc) return; try{ var c=new RTCIceCandidate(JSON.parse(m.cand)); if(pc.remoteDescription){ pc.addIceCandidate(c).catch(function(){}); } else { pendC.push(c); } }catch(e){} }); },function(){}); }catch(e){} }
function clearCands(oid){ try{ callCands(oid).get().then(function(sn){ sn.docs.forEach(function(d){ d.ref.delete().catch(function(){}); }); }).catch(function(){}); }catch(e){} }
/* ---- caller ---- */
function dial(oid){
oid=String(oid||'').trim();
if(!oid){ nt('पहले कोई active ऑर्डर खोलें, फिर Call दबाएँ'); return; }
if(st.s!=='idle'){ nt('एक कॉल पहले से चल रही है — पहले उसे End करें'); return; }
if(!window.RTCPeerConnection){ failCall('इस browser में voice-call support नहीं (Chrome use करें)'); return; }
st={s:'dial',oid:oid}; seenC={}; pendC=[]; remReady=false; muted=false; bigSpk=true;
paintOut(oid); ringStart(false);
function go(stream){ localS=stream; startCaller(oid); }
try{
if(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia){ navigator.mediaDevices.getUserMedia({audio:true}).then(go).catch(function(){ ringStop(); failCall('🎤 Microphone नहीं मिला — browser में Mic ALLOW करें, फिर try करें'); }); }
else { ringStop(); failCall('🎤 Microphone support नहीं — Chrome में खोलें'); }
}catch(e){ ringStop(); failCall('कॉल शुरू नहीं हुई'); }
}
function startCaller(oid){
var P=mkPc(oid); if(!P){ failCall('Voice engine नहीं चला'); return; }
try{ localS.getTracks().forEach(function(t){ P.addTrack(t,localS); }); }catch(e){}
listenCands(oid);
P.createOffer({offerToReceiveAudio:true}).then(function(off){ return P.setLocalDescription(off).then(function(){ return callDoc(oid).set({type:'offer',sdp:off.sdp,from:myKey(),role:ROLE,state:'ringing',ts:Date.now()}); }); }).then(function(){
try{ if(docUn) docUn(); }catch(e){}
try{ docUn=callDoc(oid).onSnapshot(function(d){ if(!d.exists||st.oid!==oid) return; var x=d.data()||{};
if(x.state==='answered'&&x.sdp&&x.role!==ROLE&&st.s==='dial'){ try{ pc.setRemoteDescription({type:'answer',sdp:x.sdp}).then(function(){ remReady=true; try{ flushC(); }catch(e){} goLive(oid); }).catch(function(){}); }catch(e){} }
else if(x.state==='declined'&&st.s!=='live'){ endCall('सामने वाले ने काट दिया',''); }
else if(x.state==='ended'&&st.s==='live'){ endCall('कॉल समाप्त',''); }
},function(){}); }catch(e){}
if(waitT) clearTimeout(waitT);
waitT=setTimeout(function(){ if(st.s==='dial'&&st.oid===oid) endCall('कोई जवाब नहीं','सामने वाला जुड़ा नहीं — 💬 Chat try करें'); },60000);
}).catch(function(){ failCall('कॉल शुरू नहीं हुई — internet check करें'); });
}
/* ---- callee ---- */
function answerCall(oid){
if(st.s!=='ringin'||st.oid!==oid) return;
st={s:'ans',oid:oid}; seenC={}; pendC=[]; remReady=false; muted=false; bigSpk=true;
paint(head('🔒','जुड़ रहे हैं…',oid,'Secure voice बन रहा है'));
try{
if(!(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia)){ failCall('Mic support नहीं'); return; }
navigator.mediaDevices.getUserMedia({audio:true}).then(function(stream){
localS=stream;
callDoc(oid).get().then(function(d){
if(!d.exists){ failCall('कॉल मिल नहीं रही (कट गई)'); return; }
var x=d.data()||{};
if(x.state!=='ringing'||!x.sdp){ failCall('कॉल पहले ही कट गई'); return; }
var P=mkPc(oid); if(!P){ failCall('Voice engine नहीं चला'); return; }
try{ localS.getTracks().forEach(function(t){ P.addTrack(t,localS); }); }catch(e){}
listenCands(oid);
P.setRemoteDescription({type:'offer',sdp:x.sdp}).then(function(){ remReady=true; try{ flushC(); }catch(e){} return P.createAnswer(); }).then(function(ans){ return P.setLocalDescription(ans).then(function(){
return callDoc(oid).update({type:'answer',sdp:ans.sdp,state:'answered',from:myKey(),role:ROLE,ansAt:Date.now()});
}); }).then(function(){ goLive(oid); liveWatch(oid); }).catch(function(){ failCall('जुड़ नहीं पाए — फिर try करें'); });
}).catch(function(){ failCall('जुड़ नहीं पाए'); });
}).catch(function(){ failCall('🎤 Mic ALLOW करें, फिर Answer दबाएँ'); });
}catch(e){ failCall('जुड़ नहीं पाए'); }
}
function liveWatch(oid){ try{ if(docUn) docUn(); }catch(e){} try{ docUn=callDoc(oid).onSnapshot(function(d){ if(st.oid!==oid) return; if(!d.exists) return; var x=d.data()||{}; if(x.state==='ended'&&st.s==='live'){ endCall('कॉल समाप्त',''); } },function(){}); }catch(e){} }
function declineCall(oid){ try{ callDoc(oid).update({state:'declined'}).catch(function(){}); }catch(e){} ringStop(); stopTimer(); unsubs(); closePc(); stopMic(); st={s:'idle',oid:''}; fsHide(); }
function goLive(oid){ st={s:'live',oid:oid}; ringStop(); stopTimer(); if(waitT){ clearTimeout(waitT); waitT=null; } vib([80,60,80]); tone(880,0,0.15,0.2); paintLive(oid); startTimer();
try{ if(remoteA){ remoteA.muted=false; remoteA.volume=1; var pr=remoteA.play(); if(pr&&pr.catch) pr.catch(function(){}); } }catch(e){}
try{ var un=function(){ try{ if(remoteA&&(remoteA.paused||remoteA.muted)){ remoteA.muted=false; remoteA.volume=1; var q=remoteA.play(); if(q&&q.catch) q.catch(function(){}); } }catch(e){} }; document.addEventListener('touchstart',un,{once:true,passive:true}); document.addEventListener('click',un,{once:true}); }catch(e){}
setTimeout(function(){ try{ if(remoteA&&remoteA.paused){ var el=document.getElementById('swCallInner'); if(el&&!document.getElementById('swcTap')){ var b=document.createElement('button'); b.id='swcTap'; b.className='swcB'; b.style.cssText='width:100%;margin-top:14px;background:linear-gradient(135deg,#ff9a3d,#ff6b00);animation:swcPulse 1.2s infinite;'; b.innerHTML='🔊 सुनने के लिए TAP करें'; b.onclick=function(){ try{ remoteA.muted=false; remoteA.volume=1; var r=remoteA.play(); if(r&&r.catch) r.catch(function(){}); }catch(e){} try{ b.remove(); }catch(x){} }; el.appendChild(b); } } }catch(e){} },2500); }
function endCall(t,s){ var oid=st.oid; ringStop(); stopTimer(); unsubs(); closePc(); stopMic(); st={s:'idle',oid:''}; if(oid){ try{ callDoc(oid).update({state:'ended',ts:Date.now()}).catch(function(){}); }catch(e){} clearCands(oid); } if(t){ paintEnd(t,s); setTimeout(function(){ fsHide(); },1600); } else { fsHide(); } }
function silentHide(){ ringStop(); stopTimer(); unsubs(); closePc(); stopMic(); st={s:'idle',oid:''}; fsHide(); }
function failCall(msg){ var oid=st.oid; ringStop(); stopTimer(); unsubs(); closePc(); stopMic(); st={s:'idle',oid:''}; if(oid) clearCands(oid); paint(head('⚠️','कॉल नहीं जुड़ी',oid||'',esc(msg)+'<br>💡 फिर try करें या 💬 Chat use करें')+'<div style="display:flex;gap:10px;margin-top:18px;"><button class="swcB" id="swcOk" style="background:#0d6efd;">ठीक है</button></div>'); bind('swcOk',function(){ fsHide(); }); }
/* ---- incoming watcher ---- */
var orderUn=null,docSubs={};
function myQuery(){ try{ var q=SWID.orderQuery(FS, ROLE==='partner'?'partner':'customer'); if(q) return q; }catch(e){} try{ if(ROLE==='partner'){ var ph=myPhone(); if(!ph||ph.length<10) return null; return FS.collection('orders').where('partnerPhone','==',ph); } var u=null; try{ u=firebase.auth().currentUser; }catch(e){} if(u&&u.uid) return FS.collection('orders').where('uid','==',u.uid); try{ var ph2=''; try{ ph2=String(localStorage.getItem('sw_user')||'').replace(/[^0-9]/g,''); }catch(e){} if(ph2&&ph2.length>=10){ if(ph2.length>10) ph2=ph2.slice(-10); return FS.collection('orders').where('mobile','==',ph2); } }catch(e){} return null; }catch(e){ return null; } }
function watchMine(){
try{ if(orderUn) orderUn(); }catch(e){} orderUn=null;
var q=null; try{ q=myQuery(); }catch(e){}
if(!q){ setTimeout(function(){ try{ watchMine(); }catch(e){} },6000); return; }
try{ orderUn=q.onSnapshot(function(sn){
var ids={};
sn.docs.forEach(function(d){ var o=d.data()||{}; var oid=o.id||d.id; if(o.status==='Completed'||o.status==='Cancelled') return; ids[oid]=1;
if(!docSubs[oid]){ (function(id){ try{ docSubs[id]=callDoc(id).onSnapshot(function(dd){ onCallDoc(id,dd); },function(){}); }catch(e){} })(oid); }
});
Object.keys(docSubs).forEach(function(k){ if(!ids[k]){ try{ docSubs[k](); }catch(e){} delete docSubs[k]; } });
},function(){}); }catch(e){}
}
function onCallDoc(oid,dd){
if(st.s!=='idle') return;
if(!dd.exists) return;
var x=dd.data()||{};
if(x.state!=='ringing'||x.type!=='offer') return;
if(x.role===ROLE) return;
if(x.from===myKey()) return;
if(!(x.ts&&(Date.now()-x.ts)<60000)) return;
st={s:'ringin',oid:oid}; paintIn(oid); ringStart(true);
if(waitT) clearTimeout(waitT);
waitT=setTimeout(function(){ if(st.s==='ringin'&&st.oid===oid){ try{ callDoc(oid).update({state:'ended'}).catch(function(){}); }catch(e){} silentHide(); } },50000);
}
/* ---- public ---- */
window.SWAgora={ APP:'SWA-OWN-v9', init:function(r){ try{ if(r) ROLE=(r==='partner')?'partner':'cust'; }catch(e){} try{ ensureUI(); }catch(e){} try{ document.addEventListener('click',function(){ try{ ac(); }catch(e){} },{once:true}); }catch(e){} setTimeout(function(){ try{ watchMine(); }catch(e){} },1200); try{ firebase.auth().onAuthStateChanged(function(){ setTimeout(function(){ try{ watchMine(); }catch(e){} },900); }); }catch(e){} setInterval(function(){ try{ watchMine(); }catch(e){} },60000); }, dial:dial, hangup:function(){ if(st.s!=='idle') endCall('कॉल समाप्त',''); }, state:function(){ return st.s; } };
console.log('%c 🔒 OWN MASKED CALL v9 (WebRTC, full-screen + vibrate/sound) ','background:#15a04a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 34 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([34, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 35 ═══ */
try {
(function(){ try{
window.openMaskCall=function(oid){
try{ oid=oid||window.__swaCustOid||window.activeChatOrderId||''; }catch(e){}
oid=String(oid||'').trim();
if(oid){ try{ SWAgora.dial(oid); }catch(e){} return; }
try{
if(typeof myOrdersQuery==='function'){
myOrdersQuery().get().then(function(sn){
var best=null; sn.docs.forEach(function(d){ var o=d.data()||{}; if(['Accepted','On the Way','Working'].indexOf(o.status)>-1){ if(!best||(o.createdAt||0)>(best.createdAt||0)) best=o; } });
if(best){ try{ SWAgora.dial(best.id||''); }catch(e){} }
else { try{ if(window.showToast) window.showToast('कोई active ऑर्डर नहीं — पहले booking करें'); }catch(e){} }
}).catch(function(){ try{ if(window.showToast) window.showToast('पहले कोई active ऑर्डर खोलें'); }catch(e){} });
return;
}
}catch(e){}
try{ if(window.showToast) window.showToast('पहले कोई active ऑर्डर खोलें, फिर Call दबाएँ'); }catch(e){}
};
SWAgora.init('cust');
}catch(e){ console.log('swcall',e); } })();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 35 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([35, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 36 ═══ */
try {
/* SewaAstra — in-app Policy / Terms / About (bina exit confirm) v8.2 */
(function(){
  if(window.__swLegalInst) return; window.__swLegalInst=1;
  function ov(){
    var d=document.getElementById('swLegalOv');
    if(d) return d;
    d=document.createElement('div'); d.id='swLegalOv';
    d.innerHTML='<div class="swl"><div class="swl-h"><div style="font-size:13px;letter-spacing:1px;opacity:.85;">SEWAASTRA</div><div class="t" style="font-size:19px;font-weight:900;margin-top:2px;"></div><div class="x">✕</div></div><div class="swl-b"></div></div>';
    document.body.appendChild(d);
    d.querySelector('.x').onclick=function(){ closeIt(); };
    d.addEventListener('click',function(e){ if(e.target===d) closeIt(); });
    return d;
  }
  function closeIt(){ var d=document.getElementById('swLegalOv'); if(d) d.classList.remove('on'); }
  var CONT={
    privacy:{t:'Privacy Policy',h:'🔒 Privacy Policy',sections:[
      ['📱 हम क्या जानकारी लेते हैं', 'Booking और सेवा के लिए आपका नाम, मोबाइल नंबर, ईमेल, घर का पता व लोकेशन। Payment जानकारी सिर्फ UPI/bank के ज़रिए।'],
      ['🔐 कौन देख सकता है', 'आपका फोन/पता सिर्फ आपके काम पर आने वाले Verified Service Partner को दिखता है — किसी और को नहीं।'],
      ['🛡️ असली नंबर सुरक्षित', 'Partner को कॉल Masked Calling से जाती है — आपका असली नंबर उसे नहीं दिखता, जब तक आप खुद न दें।'],
      ['☁️ कहाँ रहती है', 'सारी जानकारी Google Firebase (secure) में रहती है। हम आपकी जानकारी बेचते नहीं, न ही spam करते हैं।'],
      ['🗑️ मिटाना/सुधारना', 'जानकारी बदलने या हटाने के लिए app में Help & Support से संपर्क करें — 48 घंटे में कर दिया जाएगा।'],
      ['✉️ संपर्क', 'SewaAstra, Bhopal (M.P.) • App में Help से chat/कॉल करें।']
    ]},
    terms:{t:'Terms & Conditions',h:'📜 Terms & Conditions',sections:[
      ['✅ Booking', 'सेवा बुक करते ही Admin/Partner को ऑर्डर मिल जाता है। समय और पता सही भरें।'],
      ['💵 Payment', 'Online payment तुरंत, Cash भुगतान partner को काम पूरा होने पर। Coupon सिर्फ Online पर चलता है।'],
      ['↩️ Cancellation', 'Customer अपना ऑर्डर तब तक cancel कर सकता है जब तक partner काम शुरू न करे। रद्द ऑर्डर का कोई शुल्क नहीं।'],
      ['🛠️ सेवा की ज़िम्मेदारी', 'पार्टनर सिर्फ बुक की गई सेवा करता है। नुकसान की सूचना 24 घंटे में दें — Support जाँच करेगा।'],
      ['⭐ Rating & Review', 'हर काम के बाद rating/रिव्यू दें — इससे quality सुधरती है।'],
      ['🔒 Safe use', 'अपनी login जानकारी किसी को न दें। App का दुरुपयोग account बंद करवा सकता है।']
    ]},
    about:{t:'About SewaAstra',h:'ℹ️ About SewaAstra',sections:[
      ['🏠 हम कौन हैं', 'SewaAstra एक Home Services platform है — Bhopal (M.P.) से शुरू, पूरे भारत के लिए। Verified Experts घर आकर सेवा देते हैं।'],
      ['🔧 सेवाएँ', 'AC/फ्रिज repair, Plumbing, Electrician, Cleaning, Painting और बहुत कुछ — एक टैप पर।'],
      ['🤝 हमारा वादा', 'Verified partner, पक्का rate, समय पर पहुँच, और असली नंबर की सुरक्षा (Masked Call)।'],
      ['📈 हमारा मक़सद', 'भारत के हर घर को भरोसेमंद सेवा — और हर कारीगर को सीधा, बिना बिचौलिए वाला काम और कमाई।'],
      ['✉️ संपर्क', 'SewaAstra • Help: app में Support टैब • Admin: 78699 69190']
    ]}
  };
  window.swLegal=function(kind){
    var c=CONT[kind]||CONT.about;
    var d=ov();
    d.querySelector('.t').innerText=c.t;
    var b=d.querySelector('.swl-b');
    b.innerHTML='<div style="border-left:4px solid #ff6b00;background:#fff4ea;border-radius:0 12px 12px 0;padding:10px 12px;font-size:12px;font-weight:800;color:#7a3b00;line-height:1.6;">'+c.h+'</div>'+
      c.sections.map(function(s){
        return '<div style="background:#fff;border:1px solid #e8edf6;border-radius:14px;padding:12px 14px;margin:10px 0;box-shadow:0 2px 8px rgba(21,60,150,.05);">'+
        '<div style="font-weight:900;font-size:13px;color:#ff6b00;display:flex;align-items:center;gap:7px;">'+s[0]+'</div>'+
        '<div style="font-size:12px;color:#334;line-height:1.7;margin-top:5px;">'+s[1]+'</div></div>';
      }).join('')+
      '<div style="text-align:center;margin-top:14px;font-size:10px;color:#889;font-weight:700;">© 2026 SewaAstra • v8.2</div>';
    d.classList.add('on');
  };
  try{
    if(window.__exitGuard && window.__exitGuard.registerCloser){
      window.__exitGuard.registerCloser(function(){
        var d=document.getElementById('swLegalOv');
        if(d && d.classList.contains('on')){ closeIt(); return true; }
        return false;
      });
    }
  }catch(e){}
  console.log('%c 📄 IN-APP Policy/About/Terms v8.2 ','background:#0d6efd;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 36 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([36, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 37 ═══ */
try {
/* ═══════════════════════════════════════════════════════════════
   SEWAASTRA — SUNDER POPUP SYSTEM v8.3
   Har alert/confirm/prompt = beautiful in-app popup (kabhi native
   browser/GitHub jaisa popup nahi). window.alert/confirm/prompt sab
   yahin route hote hain.
   ═══════════════════════════════════════════════════════════════ */
(function(){
  if(window.__sunderUi) return; window.__sunderUi=1;
  var Z=2147483000, ov=null, box=null, cur=null;

  function el(id){ return document.getElementById(id); }
  function esc(s){ s=String(s==null?'':s); return s.replace(/[&<>"']/g,function(m){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];}); }
  function nl(s){ return esc(s).replace(/\\n/g,'<br>'); }

  function cssOnce(){
    if(document.getElementById('swSunderCss')) return;
    var st=document.createElement('style'); st.id='swSunderCss';
    st.textContent=
      '#swSOv{position:fixed;inset:0;z-index:'+Z+';display:none;align-items:center;justify-content:center;padding:18px;background:rgba(7,10,28,.62);backdrop-filter:blur(6px);}'+
      '#swSOv.on{display:flex;}'+
      '#swSBox{width:min(92vw,356px);max-height:86vh;overflow:hidden;border-radius:26px;background:#fff;color:#1b2540;box-shadow:0 30px 90px rgba(2,5,20,.6);display:flex;flex-direction:column;animation:swSIn .28s cubic-bezier(.2,1.15,.4,1);border:1px solid rgba(255,255,255,.18);}'+
      '@keyframes swSIn{from{transform:translateY(26px) scale(.95);opacity:0}to{transform:none;opacity:1}}'+
      '#swSH{background:linear-gradient(135deg,#0b1220,#26364f 55%,#ff6b00);color:#fff;padding:20px 18px 26px;text-align:center;position:relative;}'+
      '#swSH .swI{width:66px;height:66px;border-radius:50%;margin:0 auto 10px;display:flex;align-items:center;justify-content:center;font-size:30px;background:linear-gradient(135deg,#ff6b00,#ff2d95 55%,#7a2bff);box-shadow:0 8px 26px rgba(255,45,149,.45);}'+
      '#swSH .swT{font-size:17px;font-weight:900;}'+
      '#swSH .swS{font-size:12px;opacity:.85;line-height:1.6;margin-top:6px;word-break:break-word;}'+
      '#swSB{padding:16px 16px 18px;overflow-y:auto;}'+
      '#swSB .swRow{display:flex;gap:9px;margin-top:2px;}'+
      '#swSB .swB{flex:1;border:none;border-radius:14px;padding:13px 8px;font-weight:900;font-size:13px;cursor:pointer;color:#fff;}'+
      '#swSB .swIn{width:100%;box-sizing:border-box;border:2px solid #e2e8f4;border-radius:13px;padding:12px;font-size:14px;font-weight:800;outline:none;margin-top:8px;background:#f6f9ff;color:#1b2540;}'+
      '#swSB .swIn:focus{border-color:#ff6b00;background:#fff;}'+
      'body.dark-mode #swSBox, body.dark #swSBox{background:#131a2e;color:#eef2fb;}'+
      'body.dark-mode #swSB .swIn, body.dark #swSB .swIn{background:#0e1526;border-color:#2a3857;color:#eef2fb;}';
    document.head.appendChild(st);
  }
  function ensure(){
    cssOnce();
    if(ov) return;
    ov=document.createElement('div'); ov.id='swSOv';
    ov.innerHTML='<div id="swSBox"><div id="swSH"><div class="swI" id="swSI">💬</div><div class="swT" id="swST"></div><div class="swS" id="swSS"></div></div><div id="swSB"></div></div>';
    document.body.appendChild(ov);
    box=el('swSBox');
    ov.addEventListener('click',function(e){ if(e.target===ov && cur && cur.tap) close(); });
  }
  function open(o){
    ensure();
    cur=o;
    ov.classList.add('on');
    el('swSI').textContent=o.icon||'💬';
    el('swST').textContent=o.title||'SewaAstra';
    el('swSS').innerHTML=o.html||nl(o.msg||'');
    var b=el('swSB');
    b.innerHTML='';
    if(o.input){
      var inp=document.createElement('input');
      inp.type=(o.inputType)||'text';
      inp.className='swIn';
      inp.placeholder=o.ph||'';
      inp.value=(o.def==null?'':o.def);
      b.appendChild(inp);
      setTimeout(function(){ try{ inp.focus(); }catch(e){} },120);
    }
    var row=document.createElement('div'); row.className='swRow';
    function mk(txt,bg,cls,fn){
      var x=document.createElement('button'); x.className='swB '+cls;
      x.style.background=bg; x.innerHTML=txt;
      x.onclick=function(){ close(); if(fn) fn(); };
      return x;
    }
    if(o.input){
      row.appendChild(mk(o.ok||'✅ ठीक है', o.danger?'linear-gradient(135deg,#e53935,#ff6659)':'linear-gradient(135deg,#15a04a,#1fc25e)','swOk',function(){ var v=inp.value; if(o.onOk) o.onOk(v); }));
      row.appendChild(mk(o.cancel||'✕ रद्द','linear-gradient(135deg,#6b7686,#546078)','swNo',o.onCancel));
    } else if(o.buttons==='no'){
      row.appendChild(mk(o.ok||'✅ ठीक है','linear-gradient(135deg,#0d6efd,#7a5cff)','swOk',o.onOk));
    } else {
      row.appendChild(mk(o.cancel||'✕ '+(o.no||'रुकें'),'linear-gradient(135deg,#6b7686,#546078)','swNo',o.onCancel));
      row.appendChild(mk(o.ok||'✅ '+(o.yes||'हाँ'), o.danger?'linear-gradient(135deg,#e53935,#ff6659)':'linear-gradient(135deg,#0d6efd,#7a5cff)','swOk',o.onOk));
    }
    b.appendChild(row);
    return o;
  }
  function close(){ if(ov) ov.classList.remove('on'); }
  window.swUi={
    alert:function(o){ open(typeof o==='string'?{msg:o}:o); },
    confirm:function(o){ o.buttons='yn'; return open(o); },
    prompt:function(o){ o.input=true; o.tap=false; return open(o); },
    close:close
  };
  console.log('%c 💎 SUNDER POPUPS v8.3 ','background:linear-gradient(90deg,#ff2d95,#7a2bff);color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 37 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([37, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 38 ═══ */
try {
/* Native overrides — har alert/confirm/prompt ab sunder in-app popup */
(function(){
  window.alert=function(m){
    try{ if(window.showAlert){ showAlert('सूचना', String(m==null?'':m).replace(/\n/g,'<br>')); return; } }catch(e){}
    try{ swUi.alert({msg:m}); }catch(e){}
  };
  window.confirm=function(){ return false; };   /* conversions swUi.confirm use karte hain */
  window.prompt=function(){ return null; };
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 38 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([38, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 39 ═══ */
try {
/* ═══════════════════════════════════════════════════════════════
   SEWAASTRA — EXIT GUARD v8.2 (teeno apps) — सुंदर confirm popup
   • Back button / tab close / refresh / logout — bina confirm bahar nahi
   • Custom gradient modal (koi native confirm/prompt nahi)
   • In-app internal pages (Policy/About/Terms) kholne par confirm NAHI
   • window.__exitGuard.silent() = internal reload/logout bypass
   ═══════════════════════════════════════════════════════════════ */
(function(){
  if(window.__exitGuardInstalled) return; window.__exitGuardInstalled=1;
  var armed=true, silentT=0, pendingExit=false, zz=2147483600;
  var root=null, box=null, busy=null;
  var PAL={
    bg:'linear-gradient(160deg,#101c3f,#17284f 45%,#0b142e)',
    card:'linear-gradient(165deg,#ffffff,#f2f5fd)',
    ring:'linear-gradient(135deg,#ff6b00,#ff2d95,#7a2bff)',
    good:'linear-gradient(135deg,#15a04a,#1fc25e)',
    bad:'linear-gradient(135deg,#e53935,#ff6659)',
    blu:'linear-gradient(135deg,#0d6efd,#7a5cff)'
  };
  function el(id){ return document.getElementById(id); }
  function _m(){ return busy||null; }

  function ensureUI(){
    if(root) return;
    root=document.createElement('div');
    root.id='swExitRoot';
    root.innerHTML=
      '<div id="swExitBg" style="position:fixed;inset:0;background:rgba(8,10,26,.62);backdrop-filter:blur(6px);z-index:'+zz+';display:none;align-items:center;justify-content:center;padding:18px;"></div>'+
      '<div id="swExitBox" style="position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:'+(zz+1)+';width:min(92vw,352px);display:none;text-align:center;font-family:system-ui,Arial,sans-serif;overflow:hidden;border-radius:26px;box-shadow:0 30px 90px rgba(3,6,20,.65);border:1px solid rgba(255,255,255,.25);"></div>';
    document.body.appendChild(root);
    var bg=el('swExitBg');
    if(bg) bg.addEventListener('click',function(e){ if(e.target===bg){ dismiss(); } });
  }
  function render(cfg){
    ensureUI();
    var icon=(cfg&&cfg.icon)||'🚪';
    var title=(cfg&&cfg.title)||'बाहर जाना है?';
    var sub=(cfg&&cfg.sub)||'क्या आप सच में SewaAstra से बाहर जाना चाहते हैं?<br><b>रुकें</b> दबाएँ तो आप यहीं बने रहेंगे।';
    var yes=(cfg&&cfg.yes)||'हाँ, बाहर जाएँ';
    var no=(cfg&&cfg.no)||'रुकें';
    var yesBg=(cfg&&cfg.yesBg)||PAL.bad;
    var sub2=(cfg&&cfg.sub2)||'';
    var html=
      '<div style="background:'+PAL.bg+';color:#fff;padding:26px 18px 34px;position:relative;">'+
        '<div style="width:84px;height:84px;border-radius:50%;margin:0 auto 14px;background:'+PAL.ring+';display:flex;align-items:center;justify-content:center;font-size:40px;box-shadow:0 10px 34px rgba(255,45,149,.5);">'+icon+'</div>'+
        '<div style="font-size:18.5px;font-weight:900;letter-spacing:.2px;">'+title+'</div>'+
        '<div style="font-size:12px;opacity:.82;line-height:1.65;margin-top:7px;">'+sub+'</div>'+
      '</div>'+
      '<div style="background:'+PAL.card+';color:#1c2542;padding:16px 16px 18px;">'+
        (sub2?'<div style="font-size:10.5px;color:#8a93ad;line-height:1.6;margin-bottom:10px;">'+sub2+'</div>':'')+
        '<div style="display:flex;gap:9px;">'+
          '<button id="swExitYes" style="flex:1.15;border:none;border-radius:14px;padding:13px 6px;font-weight:900;font-size:13px;cursor:pointer;color:#fff;background:'+yesBg+';box-shadow:0 8px 22px rgba(0,0,0,.18);">'+yes+'</button>'+
          '<button id="swExitNo" style="flex:1;border:none;border-radius:14px;padding:13px 6px;font-weight:900;font-size:13px;cursor:pointer;background:'+PAL.blu+';color:#fff;box-shadow:0 8px 22px rgba(13,110,253,.25);">'+no+'</button>'+
        '</div>'+
      '</div>';
    box=el('swExitBox');
    box.innerHTML=html;
    box.style.background=PAL.card;
    var bg=el('swExitBg'); if(bg) bg.style.display='flex';
    box.style.display='block';
    var y=el('swExitYes'), n=el('swExitNo');
    if(y) y.onclick=function(){ try{ (cfg&&cfg.cb)(); }catch(e){ console.log(e); } hide(); };
    if(n) n.onclick=function(){ dismiss(); };
    return cfg;
  }
  function hide(){
    var bg=el('swExitBg'); if(bg) bg.style.display='none';
    var b=el('swExitBox'); if(b) b.style.display='none';
  }
  function dismiss(){ hide(); pendingExit=false; busy=null; }
  function trap(){
    try{
      if(history.state&&history.state.__swg) return;
      history.replaceState({__swg:1},'');
      history.pushState({__swg:1},'');
    }catch(e){}
  }
  function goOut(){
    pendingExit=true; armed=false; busy=null;
    hide();
    setTimeout(function(){
      try{ if(history.length>1) history.back(); }catch(e){}
      setTimeout(function(){
        try{ window.close(); }catch(e){}
        setTimeout(function(){
          if(!document.hidden){
            ensureUI();
            var b=el('swExitBox');
            if(b) b.innerHTML='<div style="background:'+PAL.bg+';color:#fff;padding:26px 16px;"><div style="font-size:40px;">👋</div><div style="font-size:15px;font-weight:900;margin-top:10px;">फिर मिलेंगे!</div><div style="font-size:11px;opacity:.8;margin-top:6px;">अब आप इस tab को बंद कर सकते हैं।</div></div>';
          }
        },800);
      },350);
    },80);
  }

  /* 🔙 Android/browser back — pehle app ke kholे हुए internal page (Policy/About/Terms/modal) band */
  window.addEventListener('popstate',function(){
    if(!armed||pendingExit) return;
    try{
      var cbs=window.__exitGuardCloseables||[];
      for(var i=0;i<cbs.length;i++){ try{ if(cbs[i]()) return; }catch(e){} }
    }catch(e){}
    render({icon:'🚪',title:'बाहर जाना है?',sub:'क्या आप सच में SewaAstra से बाहर जाना चाहते हैं?<br><b>रुकें</b> दबाएँ तो आप यहीं बने रहेंगे।',yes:'हाँ, बाहर जाएँ',no:'रुकें',cb:function(){ goOut(); }});
    busy='back';
  });
  /* 🧾 tab close / refresh / external page */
  window.addEventListener('beforeunload',function(e){
    if(!armed) return;
    if(Date.now()-silentT<1500) return;
    e.preventDefault();
    e.returnValue='';
  });

  window.__exitGuard={
    armed:function(){ return armed; },
    disarm:function(){ armed=false; },
    rearm:function(){ armed=true; trap(); },
    silent:function(){ silentT=Date.now(); armed=false; },
    trap:trap,
    askExit:function(){ render({cb:function(){ goOut(); }}); busy='back'; },
    /* ✋ कस्टम सुंदर confirm — cb() चलेगा sirf 'हाँ' par */
    confirmExit:function(cfg){ busy='custom'; render(cfg); return cfg; },
    registerCloser:function(fn){ try{ window.__exitGuardCloseables=window.__exitGuardCloseables||[]; window.__exitGuardCloseables.push(fn); }catch(e){} },
    dismiss:dismiss,
    _modal:function(){ return _m(); }
  };
  try{ trap(); }catch(e){}
  console.log('%c 🚪 EXIT GUARD v8.2 — kahi se bhi exit confirm popup ✅ ','background:linear-gradient(90deg,#e53935,#7a2bff);color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 39 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([39, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 40 ═══ */
try {
/* ═══ v9 — CHAT NOTIFICATION (sound + vibrate + popup) — customer ═══ */
(function(){
if(window.__swChatN9) return; window.__swChatN9=1;
function nt(m){ try{ if(window.showToast){ window.showToast(m); return; } }catch(e){} try{ if(window.toast){ window.toast(m); } }catch(e){} }
function vib(p){ try{ if(navigator.vibrate) navigator.vibrate(p); }catch(e){} }
var AC9=null;
function beep9(){ try{ if(!AC9){ var C=window.AudioContext||window.webkitAudioContext; if(C) AC9=new C(); } var c=AC9; if(!c) return; if(c.state==='suspended'){ c.resume().catch(function(){}); } [880,660].forEach(function(f,i){ var o=c.createOscillator(),g=c.createGain(); o.connect(g); g.connect(c.destination); o.type='sine'; o.frequency.value=f; var t=c.currentTime+i*0.22; g.gain.setValueAtTime(0.0001,t); g.gain.exponentialRampToValueAtTime(0.3,t+0.03); g.gain.exponentialRampToValueAtTime(0.0001,t+0.2); o.start(t); o.stop(t+0.25); }); }catch(e){} }
function chatOpen(oid){ try{ var m=document.getElementById('chatCallModal'); var open=m&&m.style.display==='flex'; if(!open) return false; if(oid&&window.activeChatOrderId&&window.activeChatOrderId!==oid) return false; return true; }catch(e){ return false; } }
function bell(t,b,oid){ try{ if('Notification' in window&&Notification.permission==='granted'){ var n=new Notification(t,{body:b,tag:'swc9_'+oid}); n.onclick=function(){ try{ window.focus(); }catch(e){} try{ if(window.openOrderChat) window.openOrderChat(oid); }catch(e){} try{ n.close(); }catch(e){} }; } }catch(e){} }
try{ if('Notification' in window&&Notification.permission==='default'){ var once=function(){ try{ document.removeEventListener('click',once); }catch(e){} try{ var p=Notification.requestPermission(); if(p&&p.catch) p.catch(function(){}); }catch(e){} }; document.addEventListener('click',once); } }catch(e){}
var lastN={};
function scan(){
try{
if(window.__swDotC10) return; /* v17: instant listener hai — double beep band */
if(typeof myOrdersQuery!=='function') return;
if(document.hidden) return;
myOrdersQuery().get().then(function(sn){
sn.docs.forEach(function(d){
var o=d.data()||{}; var oid=o.id||d.id;
if(o.status==='Completed'||o.status==='Cancelled') return;
var lr=0; try{ lr=parseInt(localStorage.getItem('swc_rd_'+oid)||'0',10)||0; }catch(e){}
if(!lr){ try{ localStorage.setItem('swc_rd_'+oid,String(Date.now())); }catch(e){} lastN[oid]=0; return; }
FS.collection('orders').doc(oid).collection('chats').where('ts','>',lr).get().then(function(cn){
var news=[]; cn.docs.forEach(function(cd){ var m=cd.data()||{}; if(m.sender==='partner'||m.sender==='admin') news.push(m); });
if(news.length&&!chatOpen(oid)){
if(lastN[oid]!==news.length){
beep9(); vib([120,60,120,60,220]);
var prev=news[news.length-1];
var txt=String(prev.text||'नया मैसेज');
nt('💬 नया मैसेज: '+txt.slice(0,60));
bell('💬 SewaAstra — नया मैसेज',txt.slice(0,90),oid);
}
}
lastN[oid]=news.length;
}).catch(function(){});
});
}).catch(function(){});
}catch(e){}
}
setInterval(scan,7000);
setTimeout(scan,5000);
console.log('%c 💬 CHAT NOTIFY v9 (sound+vibrate) ','background:#0d6efd;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 40 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([40, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 41 ═══ */
try {
/* ═══ v10 — SUNDER MIC PERMISSION BOX (dono apps) ═══ */
(function(){
if(window.__swMic10) return; window.__swMic10=1;
function granted(){ try{ return localStorage.getItem('sw_mic_ok')==='1'; }catch(e){ return false; } }
function ensure(){
if(document.getElementById('swMicOv')) return;
var s=document.createElement('style');
s.textContent='#swMicOv{position:fixed;inset:0;z-index:2147483640;display:none;align-items:center;justify-content:center;padding:22px;background:rgba(5,8,18,.72);backdrop-filter:blur(4px);font-family:system-ui,Arial,sans-serif;box-sizing:border-box;}#swMicOv.on{display:flex;}.swMicCard{width:100%;max-width:340px;border-radius:26px;overflow:hidden;background:#fff;color:#222;box-shadow:0 30px 80px rgba(0,0,0,.5);animation:swmIn .3s cubic-bezier(.2,1.3,.4,1);text-align:center;}@keyframes swmIn{from{transform:scale(.88) translateY(16px);opacity:0;}to{transform:none;opacity:1;}}.swMicTop{background:linear-gradient(135deg,#7a2bff,#ff2d95 60%,#ff6b00);padding:26px 18px 20px;color:#fff;}.swMicTop .mic{font-size:56px;animation:swmPu 1.6s infinite;}@keyframes swmPu{50%{transform:scale(1.15);}}.swMicB{padding:18px;}';
document.head.appendChild(s);
var d=document.createElement('div'); d.id='swMicOv';
d.innerHTML='<div class="swMicCard"><div class="swMicTop"><div class="mic">🎤</div><div style="font-weight:900;font-size:16px;margin-top:8px;">Mic Permission दें</div><div style="font-size:11.5px;opacity:.92;margin-top:5px;line-height:1.6;">Masked calling (बिना नंबर दिखे बात) के लिए<br>microphone ज़रूरी है</div></div><div class="swMicB"><div style="font-size:12px;font-weight:700;color:#555;line-height:1.9;text-align:left;">✅ आपकी आवाज़ सिर्फ़ कॉल में जाती है<br>✅ नंबर दोनों तरफ़ हमेशा छिपा रहता है<br>✅ बिना बात के Mic कभी ON नहीं होता</div><button id="swMicYes" style="width:100%;margin-top:14px;border:none;border-radius:15px;padding:15px;font-weight:900;font-size:14.5px;color:#fff;background:linear-gradient(135deg,#15a04a,#1fc25e);cursor:pointer;box-shadow:0 8px 22px rgba(21,160,74,.4);">✅ Allow Mic</button><button id="swMicNo" style="width:100%;margin-top:9px;border:none;background:none;color:#888;font-weight:800;font-size:12px;cursor:pointer;padding:8px;">बाद में</button></div></div>';
document.body.appendChild(d);
}
var pending=null;
function hide(){ var e=document.getElementById('swMicOv'); if(e) e.classList.remove('on'); }
function goNext(){ hide(); var f=pending; pending=null; if(f){ try{ f(); }catch(e){} } }
window.swAskMic=function(next){
ensure();
if(granted()){ if(next){ try{ next(); }catch(e){} } return; }
pending=next||null;
document.getElementById('swMicOv').classList.add('on');
document.getElementById('swMicYes').onclick=function(){
try{
if(!(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia)){ try{ localStorage.setItem('sw_mic_asked','1'); }catch(e){} goNext(); return; }
navigator.mediaDevices.getUserMedia({audio:true}).then(function(st){
try{ st.getTracks().forEach(function(t){ t.stop(); }); }catch(e){}
try{ localStorage.setItem('sw_mic_ok','1'); localStorage.setItem('sw_mic_asked','1'); }catch(e){}
try{ if(window.showToast) window.showToast('✅ Mic ready — अब clear बात होगी!'); else if(window.toast) window.toast('✅ Mic ready!'); }catch(e){}
goNext();
}).catch(function(){
try{ localStorage.setItem('sw_mic_asked','1'); }catch(e){}
try{ if(window.showToast) window.showToast('⚠️ Mic allow नहीं हुआ — phone Settings में Mic ON करें'); else if(window.toast) window.toast('⚠️ Mic allow करें'); }catch(e){}
goNext();
});
}catch(e){ goNext(); }
};
document.getElementById('swMicNo').onclick=function(){ try{ localStorage.setItem('sw_mic_asked','1'); }catch(e){} goNext(); };
};
try{
var _dial=window.SWAgora&&window.SWAgora.dial;
if(window.SWAgora&&typeof _dial==='function'){
window.SWAgora.dial=function(oid){ var a=arguments,self=this;
if(granted()){ return _dial.apply(self,a); }
try{ window.swAskMic(function(){ _dial.apply(self,a); }); }catch(e){ return _dial.apply(self,a); }
};
}
}catch(e){}
setTimeout(function(){ try{ var asked=false; try{ asked=!!localStorage.getItem('sw_mic_asked'); }catch(e){} if(!asked&&!granted()) window.swAskMic(null); }catch(e){} },6000);
console.log('%c 🎤 MIC PERMISSION BOX v10 ','background:#7a2bff;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 41 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([41, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 42 ═══ */
try {
/* ═══ v10 — LIVE sync badge (refresh ki jarurat nahi) ═══ */
(function(){
if(window.__swLive10) return; window.__swLive10=1;
try{
var b=document.createElement('div'); b.id='swLiveB'; b.innerHTML='⚡ Live';
document.body.appendChild(b);
function upd(){ try{ b.innerHTML=navigator.onLine?'⚡ Live':'📴 Offline'; b.style.background=navigator.onLine?'rgba(21,160,74,.75)':'rgba(180,30,30,.8)'; }catch(e){} }
window.addEventListener('online',upd); window.addEventListener('offline',upd); upd();
}catch(e){}
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 42 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([42, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 43 ═══ */
try {
/* ═══ v10 — RED DOT on Live Chat (customer) + instant listener ═══ */
(function(){
if(window.__swDotC10) return; window.__swDotC10=1;
function vib(p){ try{ if(navigator.vibrate) navigator.vibrate(p); }catch(e){} }
var AC=null;
function beep(){ try{ if(!AC){ var C=window.AudioContext||window.webkitAudioContext; if(C) AC=new C(); } var c=AC; if(!c) return; if(c.state==='suspended'){ c.resume().catch(function(){}); } [880,660].forEach(function(f,i){ var o=c.createOscillator(),g=c.createGain(); o.connect(g); g.connect(c.destination); o.type='sine'; o.frequency.value=f; var t=c.currentTime+i*0.22; g.gain.setValueAtTime(0.0001,t); g.gain.exponentialRampToValueAtTime(0.3,t+0.03); g.gain.exponentialRampToValueAtTime(0.0001,t+0.2); o.start(t); o.stop(t+0.25); }); }catch(e){} }
window.swUnread=window.swUnread||{};
function chatOpenNow(oid){ try{ var m=document.getElementById('chatCallModal'); if(!(m&&m.style.display==='flex')) return false; if(oid&&window.activeChatOrderId&&window.activeChatOrderId!==oid) return false; return true; }catch(e){ return false; } }
function paintDots(){
try{
var h=document.querySelector('#chatCallModal h3');
if(h){ var d=document.getElementById('swDotH'); var n=0; Object.keys(window.swUnread).forEach(function(k){ n+=window.swUnread[k]||0; });
if(n>0){ if(!d){ d=document.createElement('span'); d.id='swDotH'; d.className='swDot'; h.appendChild(d); } d.innerText=n>9?'9+':n; d.style.display='inline-flex'; }
else if(d){ d.style.display='none'; } }
Object.keys(window.swUnread).forEach(function(oid){
if(!(window.swUnread[oid]>0)) return;
try{
var btns=document.querySelectorAll('button[onclick*="openOrderChat"]');
for(var i=0;i<btns.length;i++){ var oc=btns[i].getAttribute('onclick')||''; if(oc.indexOf(oid)>-1&&!btns[i].querySelector('.swDot')){ var s=document.createElement('span'); s.className='swDot'; s.innerText=window.swUnread[oid]>9?'9+':window.swUnread[oid]; s.setAttribute('data-oid',oid); btns[i].appendChild(s); } }
}catch(e){}
});
}catch(e){}
}
window.swDotShow=function(oid,n){ try{ window.swUnread[oid]=n||1; paintDots(); }catch(e){} };
window.swDotClear=function(oid){ try{ delete window.swUnread[oid]; paintDots(); try{ var els=document.querySelectorAll('.swDot[data-oid="'+oid+'"]'); for(var i=0;i<els.length;i++){ els[i].remove(); } }catch(e){} }catch(e){} };
try{
var _oc=window.openOrderChat;
if(typeof _oc==='function'){ window.openOrderChat=function(oid){ try{ window.swDotClear(oid); }catch(e){} try{ return _oc.apply(this,arguments); }catch(e){} }; }
}catch(e){}
var subs={};
function ensure(){
try{
if(typeof myOrdersQuery!=='function') return;
myOrdersQuery().get().then(function(sn){
var ids={};
sn.docs.forEach(function(d){ var o=d.data()||{}; var oid=o.id||d.id; if(o.status==='Completed'||o.status==='Cancelled') return; ids[oid]=1;
if(!subs[oid]){ (function(id){ var first=true; try{ subs[id]=FS.collection('orders').doc(id).collection('chats').orderBy('ts','desc').limit(1).onSnapshot(function(ss){ if(first){ first=false; return; } ss.docChanges().forEach(function(ch){ if(ch.type!=='added') return; var m=ch.doc.data()||{}; if(!(m.sender==='partner'||m.sender==='admin')) return; if(chatOpenNow(id)) return; beep(); vib([120,60,120,60,220]); var cur=window.swUnread[id]||0; window.swDotShow(id,cur+1); try{ if(window.showToast) window.showToast('💬 नया मैसेज — लाल बिंदी वाली चैट खोलें'); }catch(e){} }); },function(){}); }catch(e){} })(oid); }
});
Object.keys(subs).forEach(function(k){ if(!ids[k]){ try{ subs[k](); }catch(e){} delete subs[k]; try{ window.swDotClear(k); }catch(e){} } });
}).catch(function(){});
}catch(e){}
}
setInterval(ensure,9000); setTimeout(ensure,4000);
setInterval(paintDots,3000);
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 43 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([43, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 44 ═══ */
try {
/* ═══ v10 — Customer OTP popup par sound+vibrate (dhyaan jaye turant) ═══ */
(function(){
if(window.__swOtpW10) return; window.__swOtpW10=1;
function vib(p){ try{ if(navigator.vibrate) navigator.vibrate(p); }catch(e){} }
function beep3(){ try{ var C=window.AudioContext||window.webkitAudioContext; if(!C) return; var c=new C(); [880,880,1170].forEach(function(f,i){ var o=c.createOscillator(),g=c.createGain(); o.connect(g); g.connect(c.destination); o.type='sine'; o.frequency.value=f; var t=c.currentTime+i*0.25; g.gain.setValueAtTime(0.0001,t); g.gain.exponentialRampToValueAtTime(0.32,t+0.03); g.gain.exponentialRampToValueAtTime(0.0001,t+0.22); o.start(t); o.stop(t+0.28); }); }catch(e){} }
try{
var mo=new MutationObserver(function(muts){
muts.forEach(function(mu){
mu.addedNodes.forEach(function(nd){
try{
if(nd&&nd.id==='wOtpBar'){ beep3(); vib([200,100,200,100,400]); try{ if(window.showToast) window.showToast('🔐 OTP aaya — partner ko batayein!'); }catch(e){} }
}catch(e){}
});
});
});
mo.observe(document.body,{childList:true,subtree:false});
}catch(e){}
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 44 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([44, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 45 ═══ */
try {
/* ═══ v12 — 📲 APP INSTALL button (home-screen) — customer ═══ */
(function(){
if(window.__swDl12) return; window.__swDl12=1;
var SW_APK_B64='';
var SW_APK_NAME='SewaAstra-Customer.apk';
function swB64Blob(b64){ var bin=atob(b64); var len=bin.length; var arr=new Uint8Array(len); for(var i=0;i<len;i++){ arr[i]=bin.charCodeAt(i); } return new Blob([arr],{type:'application/vnd.android.package-archive'}); }
function dl(){
try{
var dp=null; try{ dp=window.proDeferredPrompt||window.deferredPrompt||null; }catch(e){}
if(dp){ try{ dp.prompt(); }catch(e){} try{ if(dp.userChoice) dp.userChoice.then(function(ch){ if(ch&&ch.outcome==='accepted'){ try{ localStorage.setItem('sw_app_installed','true'); }catch(x){} try{ if(window.showToast) window.showToast('🎉 App install ho rahi hai!'); }catch(x){} } }); }catch(e){} return; }
}catch(e){}
try{ steps(); }catch(e){}
}
function steps(){
try{
showAlert('📲 App Install kaise karein',
'1️⃣ Chrome me <b>(⋮) menu</b> खोलें<br>2️⃣ <b>Add to Home screen / Install app</b> दबाएँ<br>3️⃣ <b>Add/Install</b> confirm करें — bas! 🎉<br><br>SewaAstra icon home-screen par <b>asli app jaisa</b> chalega ⚡<br><span style="font-size:11px;opacity:.75;">iPhone: Share → Add to Home Screen</span>');
}catch(e){
alert('App Install:\n1) Chrome (⋮) → Add to Home screen\n2) Add confirm karein 🎉');
}
}
window.triggerAppInstall=function(){
try{ document.getElementById('installAppModal').style.display='none'; }catch(e){}
try{ localStorage.setItem('sw_install_dismissed','true'); }catch(e){}
try{ if(window.showToast) window.showToast('📲 App install...'); }catch(e){}
dl();
};
console.log('%c ⬇️ DOWNLOAD APP v12 (customer) ','background:#15a04a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 45 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([45, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 46 ═══ */
try {
/* ═══ v13 — SETTINGS me bada ⬇️ Download App button (customer) ═══ */
(function(){
if(window.__swSetC13) return; window.__swSetC13=1;
function add(){
try{
if(document.getElementById('swSetDl')) return;
var titles=document.querySelectorAll('.settings-section-title');
var host=null;
for(var i=0;i<titles.length;i++){ if((titles[i].textContent||'').indexOf('Preferences')>-1){ host=titles[i]; break; } }
if(!host){ var items=document.querySelectorAll('.setting-item'); if(items.length) host=items[0].parentNode; }
if(!host) return;
var d=document.createElement('div'); d.id='swSetDl';
d.style.cssText='margin:12px 14px;border-radius:20px;overflow:hidden;background:linear-gradient(135deg,#ff6b00,#ff2d95 60%,#7a2bff);color:#fff;box-shadow:0 12px 30px rgba(255,45,149,.35);';
d.innerHTML='<div style="display:flex;align-items:center;gap:12px;padding:15px 16px;"><div style="font-size:40px;">📱</div><div style="flex:1;"><div style="font-weight:900;font-size:15px;">SewaAstra App</div><div style="font-size:11px;opacity:.92;">Home-screen icon • full app jaisa • tez</div></div></div><div style="padding:0 14px 14px;"><button onclick="triggerAppInstall()" style="width:100%;border:none;border-radius:14px;padding:14px;font-weight:900;font-size:14.5px;cursor:pointer;background:#fff;color:#e91e63;box-shadow:0 6px 16px rgba(0,0,0,.25);">⬇️ Download App</button></div>';
if(host.parentNode) host.parentNode.insertBefore(d,host.nextSibling);
}catch(e){}
}
setInterval(add,2500); setTimeout(add,1500);
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 46 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([46, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 47 ═══ */
try {
/* ═══ v17 — BROWSER = FULL APP (koi browser-nishan nahi) ═══ */
(function(){
if(window.__swFeel) return; window.__swFeel=1;
try{
var css=document.createElement('style');
css.textContent="html,body{overscroll-behavior:none!important;}"
+"body{-webkit-tap-highlight-color:transparent;}"
+"::-webkit-scrollbar{width:0!important;height:0!important;display:none!important;}"
+"*{scrollbar-width:none!important;}"
+"body,div,span,p,b,h1,h2,h3,h4,li{-webkit-user-select:none;user-select:none;}"
+"input,textarea,select,[contenteditable]{-webkit-user-select:text!important;user-select:text!important;}"
+"img,a,button{-webkit-touch-callout:none;}";
document.head.appendChild(css);
document.addEventListener('contextmenu',function(e){ try{ var tg=(e.target&&e.target.tagName)||''; if(/INPUT|TEXTAREA|SELECT/.test(tg)) return; }catch(x){} try{ e.preventDefault(); }catch(y){} },true);
document.addEventListener('dblclick',function(e){ try{ e.preventDefault(); }catch(x){} },{passive:false});
document.addEventListener('gesturestart',function(e){ try{ e.preventDefault(); }catch(x){} });
document.addEventListener('touchstart',function(e){
try{
var el=e.target;
for(var k=0;k<7&&el&&el!==document.documentElement;k++){
var cs=null; try{ cs=getComputedStyle(el); }catch(c){ break; }
if(cs&&(cs.overflowY==='auto'||cs.overflowY==='scroll')&&el.scrollHeight>el.clientHeight+4){
el.style.touchAction='pan-y'; el.style.webkitOverflowScrolling='touch'; break;
}
el=el.parentNode;
}
}catch(x){}
},{passive:true});
}catch(e){}
console.log('%c 📱 APP-FEEL v17 (browser hi app hai) ','background:#0d6efd;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 47 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([47, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 48 ═══ */
try {
/* ═══ v20 — ONE-FINGER SCROLL GUARANTEE (native + manual backup) ═══ */
(function(){
if(window.__swScr20) return; window.__swScr20=1;
var sx=0, sy=0, on=false, down=false, vy=0, lastY=0, lastT=0, glide=null;
function stopGlide(){ if(glide){ try{ cancelAnimationFrame(glide); }catch(e){} glide=null; } }
function innerScroller(el){
try{
for(var k=0;k<7&&el&&el!==document.documentElement;k++){
if(el.id==='leafletMapModal'||(el.className&&/leaflet-container|chat-box|chatMsgContainer|modal-box|ovl-card/i.test(String(el.className)))) return true;
try{
var cs=getComputedStyle(el);
if(cs&&(cs.overflowY==='auto'||cs.overflowY==='scroll')&&el.scrollHeight>el.clientHeight+4) return true;
}catch(c){}
el=el.parentNode;
}
}catch(x){}
return false;
}
document.addEventListener('touchstart',function(e){
down=false; on=false;
try{
if(!e.touches||e.touches.length!==1) return;
var t=e.target, tag=(t&&t.tagName)||'';
if(/INPUT|TEXTAREA|SELECT|VIDEO|AUDIO/.test(tag)) return;
if(innerScroller(t)) return;
sx=e.touches[0].clientX; sy=e.touches[0].clientY; down=true; vy=0; lastY=sy; lastT=Date.now(); stopGlide();
}catch(x){}
},{passive:true});
document.addEventListener('touchmove',function(e){
try{
if(!down||!e.touches||e.touches.length!==1){ on=false; return; }
var nx=e.touches[0].clientX, ny=e.touches[0].clientY;
var dx=nx-sx, dy=ny-sy;
if(!on){
if(Math.abs(dy)<12) return;
if(Math.abs(dx)>Math.abs(dy)*1.4){ down=false; return; }
on=true;
}
try{ e.preventDefault(); }catch(x){}
try{ var now=Date.now(), dt=Math.max(8,now-lastT); var step=dy*1.4; window.scrollBy(0,-step); vy=0.75*vy+0.25*(dy/dt*16); lastT=now; }catch(y){}
sx=nx; sy=ny;
}catch(x){}
},{passive:false});
document.addEventListener('touchend',function(){ down=false; var g=on; on=false; try{ if(g&&Math.abs(vy)>1){ stopGlide(); var f=function(){ vy*=0.94; if(Math.abs(vy)<0.6||down){ glide=null; return; } try{ window.scrollBy(0,-vy); }catch(e){ glide=null; return; } glide=requestAnimationFrame(f); }; glide=requestAnimationFrame(f); } }catch(e){} },{passive:true});
document.addEventListener('touchcancel',function(){ down=false; on=false; try{ stopGlide(); }catch(e){} },{passive:true});
console.log('%c 👆 FAST SCROLL v21 ','background:#15a04a;color:#fff;font-weight:bold;padding:3px;');
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 48 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([48, String(e)]); } catch (_) {} }

/* ═══ ब्लॉक 49 ═══ */
try {
/* ═══ v21 — 3 SECOND AUTO SYNC (bina dikhe, bina net-ghehra) — customer ═══ */
(function(){
if(window.__swTick21) return; window.__swTick21=1; window.__swOrdT=0;
setInterval(function(){
try{ if(document.hidden) return; }catch(e){}
try{ var b=document.getElementById('swLiveB'); if(b){ var on=navigator.onLine; b.innerHTML=on?'⚡ Live':'📴 Offline'; b.style.background=on?'rgba(21,160,74,.75)':'rgba(180,30,30,.8)'; } }catch(e){}
try{ var h=document.getElementById('swDotH'); }catch(e){} try{ var __nt=Date.now(); if(!__swOrdT||__nt-__swOrdT>60000){ __swOrdT=__nt; if(localStorage.getItem('sw_logged')==='true'&&typeof startMyOrdersListener==='function'){ startMyOrdersListener(); } } }catch(e){}
},3000);
})();
} catch (e) { try { console.error('[SewaAstra] ब्लॉक 49 में गड़बड़:', e); (window.__SW_ERRORS = window.__SW_ERRORS || []).push([49, String(e)]); } catch (_) {} }
