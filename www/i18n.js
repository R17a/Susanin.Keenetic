/* Susanin.Keenetic — i18n веб-панели.
 *
 * Словари — отдельные файлы: www/lang/RU.JSON | EN.JSON | ZH.JSON.
 * Формат — плоский JSON: {"ключ": "текст", ...}; в тексте можно писать
 * подстановки {name}. Правила ключей и порядок добавления языка —
 * docs/WEB-I18N.md.
 *
 * Ключевые свойства:
 *  - язык по умолчанию — русский (автоопределение по браузеру НЕ делаем);
 *  - выбор запоминается в localStorage('susanin_lang');
 *  - если словарь не загрузился (старый агент/403/404/битый JSON), панель
 *    продолжает работать на русских литералах из кода — пустых мест не бывает;
 *  - отсутствующий в словаре ключ берётся из RU.JSON, затем из литерала,
 *    который передан вторым аргументом t().
 *
 * Публичный API: window.I18N = { t, set, ready, apply, lang, names,
 *                                supported, beforeChange }.
 * Событие смены языка: document 'susanin:lang' (detail.lang).
 */
(function () {
  'use strict';

  var SUPPORTED = ['ru', 'en', 'zh'];
  var DEFAULT = 'ru';
  var NAMES = { ru: 'Русский', en: 'English', zh: '中文' };
  var FILES = { ru: 'lang/RU.JSON', en: 'lang/EN.JSON', zh: 'lang/ZH.JSON' };
  /* Атрибут lang у <html>: для китайского нужен zh-Hans, а не «zh». */
  var LANG_ATTR = { ru: 'ru', en: 'en', zh: 'zh-Hans' };
  var STORE_KEY = 'susanin_lang';
  var TIMEOUT_MS = 4000;

  /* Каталог, откуда загружен этот скрипт, — база для путей к словарям.
   * Так панель работает и из корня (/), и из подкаталога. */
  var BASE = (function () {
    var s = document.currentScript;
    if (s && s.src) return s.src.replace(/[?#].*$/, '').replace(/[^/]*$/, '');
    return './';
  })();

  var dict = null;      /* словарь выбранного языка */
  var ruDict = null;    /* резервный словарь (RU) */
  var cache = {};       /* код -> словарь */
  var lang = DEFAULT;
  var isReady = false;
  var readyCbs = [];

  function normalize(l) {
    l = String(l || '').toLowerCase();
    return SUPPORTED.indexOf(l) === -1 ? DEFAULT : l;
  }

  function storedLang() {
    try { return normalize(localStorage.getItem(STORE_KEY) || ''); } catch (e) { return DEFAULT; }
  }

  function storeLang(l) {
    try { localStorage.setItem(STORE_KEY, l); } catch (e) { /* приватный режим */ }
  }

  function format(s, vars) {
    if (!vars) return String(s);
    return String(s).replace(/\{(\w+)\}/g, function (m, k) {
      return Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : m;
    });
  }

  /* Сырое значение из словаря (без литералов) — для статики: не нашли ключ,
   * значит оставляем исходную разметку как есть (она на русском). */
  function raw(key) {
    if (dict && dict[key] != null) return dict[key];
    if (ruDict && ruDict[key] != null) return ruDict[key];
    return null;
  }

  function t(key, fallback, vars) {
    var v = raw(key);
    if (v == null) v = (fallback == null ? key : fallback);
    return format(v, vars);
  }

  function notify(msg) {
    if (typeof window.susaninToast === 'function') {
      window.susaninToast(msg, false);
    } else if (window.console && console.warn) {
      console.warn('i18n: ' + msg);
    }
  }

  function fetchJson(url) {
    if (!window.fetch) return Promise.reject(new Error('no fetch'));
    var opts = { cache: 'no-store', credentials: 'same-origin' };
    var ctrl = null, timer = null;
    try {
      if (window.AbortController) {
        ctrl = new window.AbortController();
        opts.signal = ctrl.signal;
      }
    } catch (e) { ctrl = null; }

    var req = fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });

    if (!ctrl) return req;
    var timeout = new Promise(function (_, reject) {
      timer = window.setTimeout(function () {
        try { ctrl.abort(); } catch (e) {}
        reject(new Error('timeout'));
      }, TIMEOUT_MS);
    });
    return Promise.race([req, timeout]).then(function (v) {
      window.clearTimeout(timer);
      return v;
    }, function (e) {
      window.clearTimeout(timer);
      throw e;
    });
  }

  function load(code) {
    if (cache[code]) return Promise.resolve(cache[code]);
    return fetchJson(BASE + FILES[code]).then(function (d) {
      if (!d || typeof d !== 'object' || Object.prototype.toString.call(d) === '[object Array]')
        throw new Error('bad dictionary');
      cache[code] = d;
      if (code === 'ru') ruDict = d;
      return d;
    });
  }

  function each(sel, fn) {
    var list = document.querySelectorAll(sel);
    for (var i = 0; i < list.length; i++) fn(list[i]);
  }

  /* Применяем словарь к статической разметке index.html.
   * data-i18n       -> textContent
   * data-i18n-html  -> innerHTML (для строк с <code>/<b>; словарь локальный)
   * data-i18n-title -> title (и aria-label, если он есть)
   * data-i18n-ph    -> placeholder */
  function apply(root) {
    root = root && root.querySelectorAll ? root : document;
    var q = function (sel) { return root.querySelectorAll(sel); };
    var i, el, v;

    var plain = q('[data-i18n]');
    for (i = 0; i < plain.length; i++) {
      el = plain[i];
      v = raw(el.getAttribute('data-i18n'));
      if (v != null) el.textContent = v;
    }
    var html = q('[data-i18n-html]');
    for (i = 0; i < html.length; i++) {
      el = html[i];
      v = raw(el.getAttribute('data-i18n-html'));
      if (v != null) el.innerHTML = v;
    }
    var titles = q('[data-i18n-title]');
    for (i = 0; i < titles.length; i++) {
      el = titles[i];
      v = raw(el.getAttribute('data-i18n-title'));
      if (v == null) continue;
      el.setAttribute('title', v);
      if (el.hasAttribute('aria-label')) el.setAttribute('aria-label', v);
    }
    var phs = q('[data-i18n-ph]');
    for (i = 0; i < phs.length; i++) {
      el = phs[i];
      v = raw(el.getAttribute('data-i18n-ph'));
      if (v != null) el.setAttribute('placeholder', v);
    }
    if (document.title) document.title = t('app.title', document.title);
  }

  function buildSelect() {
    var sel = document.getElementById('lang');
    if (!sel) return;
    sel.innerHTML = '';
    SUPPORTED.forEach(function (code) {
      var o = document.createElement('option');
      o.value = code;
      o.textContent = NAMES[code];
      sel.appendChild(o);
    });
    sel.value = lang;
    sel.addEventListener('change', function () { setLang(sel.value); });
  }

  function syncSelect() {
    var sel = document.getElementById('lang');
    if (sel) sel.value = lang;
  }

  function fire() {
    try {
      document.dispatchEvent(new CustomEvent('susanin:lang', { detail: { lang: lang } }));
    } catch (e) {
      var ev = document.createEvent('CustomEvent');
      ev.initCustomEvent('susanin:lang', false, false, { lang: lang });
      document.dispatchEvent(ev);
    }
  }

  function setLang(code) {
    code = normalize(code);
    var API = window.I18N;
    if (code === lang) { syncSelect(); return Promise.resolve(true); }
    /* dirty-guard: страница может запретить смену (например, несохранённый
     * конфиг) — тогда просто возвращаем селектор на прежнее значение. */
    if (API && typeof API.beforeChange === 'function') {
      var ok = false;
      try { ok = API.beforeChange(code) !== false; } catch (e) { ok = true; }
      if (!ok) { syncSelect(); return Promise.resolve(false); }
    }
    return load(code).then(function (d) {
      lang = code;
      dict = d;
      storeLang(code);
      document.documentElement.setAttribute('lang', LANG_ATTR[code] || code);
      apply(document);
      syncSelect();
      fire();
      return true;
    }, function () {
      notify(t('err.lang.load', 'Не удалось загрузить язык: {lang}', { lang: NAMES[code] || code }));
      syncSelect();
      return false;
    });
  }

  function ready(cb) {
    if (typeof cb !== 'function') return;
    if (isReady) { cb(); return; }
    readyCbs.push(cb);
  }

  function finishBoot() {
    isReady = true;
    apply(document);
    document.documentElement.classList.remove('i18n-pending');
    var cbs = readyCbs;
    readyCbs = [];
    for (var i = 0; i < cbs.length; i++) {
      try { cbs[i](); } catch (e) { if (window.console) console.error(e); }
    }
    fire();
  }

  window.I18N = {
    t: t,
    get lang() { return lang; },
    names: NAMES,
    supported: SUPPORTED,
    beforeChange: null,
    set: setLang,
    ready: ready,
    apply: apply
  };

  /* --- старт: сразу читаем выбор и начинаем загрузку, разметку трогаем
   * только после готовности DOM (скрипт стоит в <head>). --- */
  lang = storedLang();
  dict = null;
  document.documentElement.setAttribute('lang', LANG_ATTR[lang] || lang);
  document.documentElement.classList.add('i18n-pending');

  var domReady = new Promise(function (resolve) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', resolve);
    } else {
      resolve();
    }
  });

  var firstLoad = load(lang).then(function (d) {
    dict = d;
    return true;
  }, function () {
    return false;
  });

  /* RU грузим всегда: он резерв для пропущенных ключей и для случая, когда
   * выбранный язык недоступен. Ошибка здесь не критична. */
  var ruLoad = load('ru').catch(function () { return null; });

  Promise.all([domReady, firstLoad, ruLoad]).then(function (res) {
    if (!res[1]) {
      notify(t('err.lang.load', 'Не удалось загрузить язык: {lang}', { lang: NAMES[lang] || lang }));
    }
    buildSelect();
    finishBoot();
  });
})();
