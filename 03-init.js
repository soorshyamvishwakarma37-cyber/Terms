/* SewaAstra Customer — 03-init.js */
/* Firebase config / शुरुआती setup. */

/* ═══ inline ब्लॉक 1/1 ═══ */
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
