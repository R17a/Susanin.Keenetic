/* Susanin.Keenetic — веб-панель (W2/W3, без внешних зависимостей).
 * Данные: GET /api/status, GET /api/list?name=..., GET /api/log,
 * GET /api/choices (известные системе интерфейсы/подсети/таблицы/метки/файлы
 * списков — их подставляет www/config.js в выпадающие списки полей).
 * Токен хранится в localStorage и передаётся заголовком X-Auth-Token (либо
 * один раз через ?token=...). Списки vpn_always/vpn_never редактируются
 * перетаскиванием между колонками (или стрелкой на записи — для touch). */
(function () {
  'use strict';

  var TOKEN_KEY = 'susanin_token';
  var LISTS = ['vpn_always', 'vpn_never'];
  /* Подписи списков — из словаря языка (fallback — прежние русские строки). */
  var LIST_LABEL_KEY = { vpn_always: 'list.label.always', vpn_never: 'list.label.never' };
  var LIST_LABEL_RU = { vpn_always: 'через VPN', vpn_never: 'напрямую' };

  var qs = new URLSearchParams(window.location.search);
  if (qs.get('token')) {
    try { localStorage.setItem(TOKEN_KEY, qs.get('token')); } catch (e) {}
    qs.delete('token');
    var clean = window.location.pathname + (qs.toString() ? '?' + qs.toString() : '');
    window.history.replaceState({}, '', clean);
  }
  var token = '';
  try { token = localStorage.getItem(TOKEN_KEY) || ''; } catch (e) {}

  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) {
    return String(s === null || s === undefined ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  };

  /* Перевод строк интерфейса. i18n.js подключается в index.html раньше, но
   * если его нет (старый кэш, другой потребитель www) — работают литералы. */
  function T(key, fallback, vars) {
    return (window.I18N && window.I18N.t) ? window.I18N.t(key, fallback, vars) : fallback;
  }
  function listLabel(name) { return T(LIST_LABEL_KEY[name], LIST_LABEL_RU[name]); }

  /* --- «известные системе» значения (один запрос на всю панель) ---
   * config.js читает window.susaninChoices при отрисовке полей. Запрос делаем
   * ровно один раз при открытии панели и кэшируем; ошибка/отсутствие токена —
   * тихий фолбэк: подсказок нет, поля работают как раньше (ручной ввод).
   * Событие susanin:choices нужно на случай, когда config.js отрисовался
   * раньше, чем пришёл ответ. */
  window.susaninChoices = null;

  function loadChoices() {
    return api('/api/choices').then(function (t) {
      var d;
      try { d = JSON.parse(t); } catch (e) { return null; }
      if (!d || typeof d !== 'object') return null;
      window.susaninChoices = d;
      try {
        document.dispatchEvent(new CustomEvent('susanin:choices', { detail: d }));
      } catch (e) { /* старый браузер — config.js просто не перерисует */ }
      return d;
    }).catch(function () { return null; });
  }


  /* Читаемая ошибка вместо «Unexpected token»: сервер может ответить текстом
   * (старые сборки) или JSON {"ok":false,"error":"…"} (RC1+). */
  function respErr(r) {
    return r.text().then(function (t) {
      var msg = (t || '').trim();
      try {
        var j = JSON.parse(msg);
        if (j && j.error) msg = j.error;
      } catch (e) { /* не JSON — оставляем текст как есть */ }
      if (r.status === 401) msg = T('err.token', 'нужен токен (обновите страницу с ?token=…)');
      else if (r.status === 403) {
        msg = T('err.readonly', 'панель только для чтения: задайте токен — ' +
              'susanin-agent config set web_token <секрет>, затем susanin restart');
      } else if (r.status === 413) msg = T('err.toolarge', 'список больше 64 КБ — правьте его на роутере');
      else if (!msg) msg = 'HTTP ' + r.status;
      return new Error(msg);
    }).catch(function () { return new Error('HTTP ' + r.status); });
  }

  function api(path) {
    var headers = {};
    if (token) headers['X-Auth-Token'] = token;
    return fetch(path, { headers: headers, cache: 'no-store' }).then(function (r) {
      if (!r.ok) return respErr(r).then(function (e) { throw e; });
      return r.text();
    });
  }

  function post(path, params) {
    var body = Object.keys(params).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
    }).join('&');
    var headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (token) headers['X-Auth-Token'] = token;
    return fetch(path, { method: 'POST', headers: headers, body: body }).then(function (r) {
      if (!r.ok) return respErr(r).then(function (e) { throw e; });
      return r.json().catch(function () {
        return { ok: false, error: T('err.badJson', 'плохой ответ сервера') };
      });
    });
  }

  function toast(msg, ok) {
    var box = $('toast');
    var el = document.createElement('div');
    el.className = 'msg' + (ok ? '' : ' err');
    el.textContent = msg;
    box.appendChild(el);
    window.setTimeout(function () { el.remove(); }, 3000);
  }

  /* i18n.js показывает этим тостом свои ошибки (не загрузился словарь языка). */
  window.susaninToast = toast;

  function setConn(ok) {
    var d = $('dot');
    d.className = 'dot ' + (ok ? 'ok' : 'err');
  }

  function doPost(path, params, label) {
    return post(path, params).then(function (r) {
      if (r && r.ok) { toast(T('toast.opOk', '{op}: ок', { op: label }), true); return true; }
      toast(T('toast.opErr', '{op}: {err}', {
        op: label, err: (r && r.error) || T('err.unknown', 'ошибка')
      }), false);
      return false;
    }).catch(function (e) {
      toast(T('toast.opErr', '{op}: {err}', { op: label, err: e.message }), false);
      return false;
    });
  }

  $('reload').onclick = function () { doPost('/api/reload', {}, T('op.reload', 'reload')).then(loadAll); };
  $('rescan').onclick = function () { doPost('/api/rescan', {}, T('op.rescan', 'rescan')).then(loadAll); };
  $('restart').onclick = function () { doPost('/api/restart', {}, T('op.restart', 'restart')).then(loadAll); };
  $('reset').onclick = function () {
    var ip = $('fip').value.trim();
    if (!ip) { toast(T('toast.resetNeed', 'reset: укажите IP или домен'), false); return; }
    doPost('/api/reset', { ip: ip }, T('op.reset', 'reset {value}', { value: ip }));
  };

  function renderStatus(d) {
    $('ver').textContent = 'v' + d.version;
    var upd = $('verupd');
    if (upd) {
      var latest = d.version_latest || '';
      var avail = !!d.update_available && !!latest;
      upd.hidden = !avail;
      if (avail) {
        var tip = T('app.verupd', 'Есть обновление до версии {version}', { version: latest });
        upd.title = tip;
        upd.setAttribute('aria-label', tip);
        upd.setAttribute('data-tip', tip);
        upd.href = d.release_url || '#status';
      } else {
        upd.title = '';
        upd.removeAttribute('data-tip');
      }
    }
    var tb = document.querySelector('#sets tbody');
    tb.innerHTML = '';
    var ipsets = d.ipsets || {};
    Object.keys(ipsets).forEach(function (k) {
      tb.insertAdjacentHTML('beforeend',
        '<tr><td>' + esc(k) + '</td><td>' + esc(ipsets[k]) + '</td></tr>');
    });
    var rv = d.ru_in_vpn || null;
    var rvel = document.getElementById('ru-in-vpn');
    if (rvel) {
      if (!rv) {
        rvel.textContent = '—';
      } else if (rv.count > 0) {
        rvel.textContent = rv.count + ': ' + (rv.domains || '');
        rvel.className = 'warn';
      } else {
        rvel.textContent = T('status.ru.zero', '0 — норма');
        rvel.className = 'muted';
      }
    }
  }

  function load() {
    api('/api/status').then(function (t) {
      var d;
      try { d = JSON.parse(t); } catch (e) { throw new Error('bad JSON'); }
      lastStatus = d;
      renderStatus(d);
      setConn(true);
    }).catch(function () {
      setConn(false);
    });

    api('/api/log?lines=200').then(function (t) {
      var el = $('log');
      el.textContent = t || T('status.log.empty', '(пусто)');
      el.scrollTop = el.scrollHeight;
    }).catch(function () { /* лог не критичен */ });
  }

  /* --- Списки vpn_always / vpn_never: drag & drop между колонками --- */

  var lastStatus = null;
  var lists = { vpn_always: [], vpn_never: [] };
  var filters = { vpn_always: '', vpn_never: '' };
  var listErrors = { vpn_always: null, vpn_never: null };

  function fetchList(name) {
    return api('/api/list?name=' + name).then(function (t) {
      listErrors[name] = null;
      try { return JSON.parse(t); } catch (e) {
        listErrors[name] = T('err.badJson', 'плохой ответ сервера');
        return null;
      }
    }).catch(function (e) {
      listErrors[name] = e.message || T('err.unknown', 'ошибка');
      return null;
    });
  }

  function loadLists() {
    return Promise.all(LISTS.map(fetchList)).then(function (res) {
      LISTS.forEach(function (name, i) {
        if (res[i] !== null) lists[name] = res[i];
      });
      renderLists();
    });
  }

  function renderLists() {
    LISTS.forEach(function (name) {
      var items = lists[name].filter(function (v) {
        return !filters[name] || v.toLowerCase().indexOf(filters[name]) !== -1;
      });
      $('cnt-' + name).textContent = lists[name].length;
      var box = $('items-' + name);
      box.innerHTML = '';
      if (listErrors[name]) {
        box.innerHTML = '<div class="list-empty err">' +
          esc(T('list.loadFail', 'не удалось загрузить: {err}', { err: listErrors[name] })) + '</div>';
        return;
      }
      if (!items.length) {
        box.innerHTML = '<div class="list-empty">' +
          esc(lists[name].length ? T('list.noMatch', 'ничего не найдено')
                                 : T('list.empty', 'список пуст')) + '</div>';
        return;
      }
      items.forEach(function (v) {
        box.appendChild(makeItem(name, v));
      });
    });
  }

  function otherList(name) { return name === 'vpn_always' ? 'vpn_never' : 'vpn_always'; }

  function makeItem(name, value) {
    var row = document.createElement('div');
    row.className = 'list-item';
    row.draggable = true;
    row.title = value;

    var handle = document.createElement('span');
    handle.className = 'handle';
    handle.textContent = '⋮⋮';
    row.appendChild(handle);

    var val = document.createElement('span');
    val.className = 'val';
    val.textContent = value;
    row.appendChild(val);

    var move = document.createElement('button');
    move.className = 'btn-icon move';
    move.title = T('list.moveTo', 'Переместить в «{label}»', { label: listLabel(otherList(name)) });
    move.textContent = name === 'vpn_always' ? '→' : '←';
    move.onclick = function () { moveEntry(value, name, otherList(name)); };
    row.appendChild(move);

    var del = document.createElement('button');
    del.className = 'btn-icon del';
    del.title = T('list.remove', 'Удалить из списка');
    del.textContent = '×';
    del.onclick = function () { deleteEntry(value, name); };
    row.appendChild(del);

    row.addEventListener('dragstart', function (e) {
      e.dataTransfer.setData('text/plain', JSON.stringify({ value: value, from: name }));
      e.dataTransfer.effectAllowed = 'move';
      row.classList.add('dragging');
    });
    row.addEventListener('dragend', function () { row.classList.remove('dragging'); });

    return row;
  }

  LISTS.forEach(function (name) {
    var box = $('items-' + name);
    box.addEventListener('dragover', function (e) {
      e.preventDefault();
      box.classList.add('drag-over');
    });
    box.addEventListener('dragleave', function () { box.classList.remove('drag-over'); });
    box.addEventListener('drop', function (e) {
      e.preventDefault();
      box.classList.remove('drag-over');
      var raw = e.dataTransfer.getData('text/plain');
      if (!raw) return;
      var data;
      try { data = JSON.parse(raw); } catch (err) { return; }
      if (data.from === name) return;
      moveEntry(data.value, data.from, name);
    });

    $('filter-' + name).addEventListener('input', function () {
      filters[name] = this.value.trim().toLowerCase();
      renderLists();
    });

    var addInput = $('add-' + name);
    var addFn = function () {
      var v = addInput.value.trim();
      if (!v) return;
      doPost('/api/list', { list: name, op: 'add', value: v },
             T('op.add', 'добавить {value}', { value: v }))
        .then(function (ok) { if (ok) { addInput.value = ''; loadLists(); } });
    };
    addInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') addFn(); });
  });

  document.querySelectorAll('[data-add]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var name = btn.getAttribute('data-add');
      var input = $('add-' + name);
      var v = input.value.trim();
      if (!v) return;
      doPost('/api/list', { list: name, op: 'add', value: v },
             T('op.add', 'добавить {value}', { value: v }))
        .then(function (ok) { if (ok) { input.value = ''; loadLists(); } });
    });
  });

  function deleteEntry(value, from) {
    doPost('/api/list', { list: from, op: 'del', value: value },
           T('op.del', 'удалить {value}', { value: value }))
      .then(function (ok) { if (ok) loadLists(); });
  }

  function moveEntry(value, from, to) {
    doPost('/api/list', { list: from, op: 'del', value: value },
           T('op.del', 'удалить {value}', { value: value })).then(function (ok) {
      if (!ok) return;
      doPost('/api/list', { list: to, op: 'add', value: value },
             T('op.add', 'добавить {value}', { value: value })).then(function (ok2) {
        if (ok2) toast(value + ' → ' + listLabel(to), true);
        loadLists();
      });
    });
  }

  /* --- Memo-редактор списка: весь файл текстом (с комментариями) --- */

  var memoName = null;
  var memoLoaded = false;   /* «Сохранить» активна только после успешной загрузки:
                             * иначе сохранение пустого textarea стёрло бы список */

  function memoSetSaveEnabled(on) {
    memoLoaded = !!on;
    $('memo-save').disabled = !on;
    $('memo-save').title = on ? T('memo.saveTip', 'Записать весь список')
                              : T('memo.saveTipDisabled', 'Сначала дождитесь загрузки списка');
    $('memo-text').readOnly = !on;
  }

  /* Читаемая ошибка вместо «Unexpected token» при текстовом ответе (401/413/400). */
  function httpError(r) {
    return r.text().then(function (t) {
      var msg = (t || '').trim();
      if (r.status === 401) msg = T('err.token', 'нужен токен (обновите страницу с ?token=…)');
      else if (r.status === 413) msg = T('err.toolarge', 'список больше 64 КБ — правьте его на роутере');
      else if (!msg) msg = 'HTTP ' + r.status;
      return { ok: false, error: msg };
    }).catch(function () { return { ok: false, error: 'HTTP ' + r.status }; });
  }

  function memoOpen(name) {
    memoName = name;
    memoSetSaveEnabled(false);
    $('memo-title').textContent = T('memo.titleOf', 'Список: {name}', {
      name: name === 'vpn_always' ? T('list.always.title', 'Всегда через VPN')
                                  : T('list.never.title', 'Всегда напрямую')
    });
    $('memo-status').textContent = T('memo.loading', 'загрузка…');
    $('memo-text').value = '';
    $('memo').hidden = false;
    api('/api/list/raw?name=' + encodeURIComponent(name)).then(function (t) {
      if (memoName !== name) return;
      $('memo-text').value = t;
      var n = t.split('\n').filter(function (l) { return l.trim() && l.trim()[0] !== '#'; }).length;
      $('memo-status').textContent = T('memo.loaded', 'загружено записей: {n}', { n: n });
      memoSetSaveEnabled(true);
      $('memo-text').focus();
    }).catch(function (e) {
      /* Сохранение остаётся заблокированным: не даём стереть список сбоем загрузки. */
      memoSetSaveEnabled(false);
      $('memo-status').textContent = T('memo.loadFail',
        'не удалось загрузить: {err} — сохранение отключено',
        { err: e.message || T('err.unknown', 'ошибка') });
    });
  }

  function memoClose() {
    memoName = null;
    memoSetSaveEnabled(false);
    $('memo').hidden = true;
  }

  function memoSave() {
    if (!memoName || !memoLoaded) return;
    var name = memoName;
    var text = $('memo-text').value;
    var headers = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (token) headers['X-Auth-Token'] = token;
    $('memo-status').textContent = T('memo.saving', 'сохранение…');
    $('memo-save').disabled = true;
    fetch('/api/list/save?name=' + encodeURIComponent(name), {
      method: 'POST', headers: headers, body: text
    }).then(function (r) {
      if (r.ok) return r.json().catch(function () {
        return { ok: false, error: T('err.badJson', 'плохой ответ сервера') };
      });
      return httpError(r);
    }).then(function (r) {
      $('memo-save').disabled = false;
      if (!r || !r.ok) {
        $('memo-status').textContent = T('memo.error', 'ошибка: {err}', {
          err: (r && r.error) || T('memo.notSaved', 'не сохранено')
        });
        toast(T('memo.notSaved', 'список не сохранён'), false);
        return;
      }
      var msg = T('memo.saved', 'сохранено записей: {n}', { n: r.kept });
      if (r.dropped) msg += T('memo.dropped', ', отброшено строк: {n}', { n: r.dropped });
      $('memo-status').textContent = msg;
      toast(name + ': ' + msg, !r.dropped);
      memoClose();
      loadLists();
    }).catch(function (e) {
      $('memo-save').disabled = false;
      $('memo-status').textContent = T('memo.error', 'ошибка: {err}', { err: e.message || e });
      toast(T('memo.notSaved', 'список не сохранён'), false);
    });
  }

  document.querySelectorAll('[data-memo]').forEach(function (btn) {
    btn.addEventListener('click', function () { memoOpen(btn.getAttribute('data-memo')); });
  });
  $('memo-save').onclick = memoSave;
  $('memo-cancel').onclick = memoClose;
  $('memo-close').onclick = memoClose;
  $('memo').addEventListener('click', function (e) { if (e.target === $('memo')) memoClose(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !$('memo').hidden) memoClose();
    /* Ctrl/Cmd+S — сохранить список из модального окна */
    if ((e.ctrlKey || e.metaKey) && e.key === 's' && !$('memo').hidden) {
      e.preventDefault();
      memoSave();
    }
  });

  /* --- Вкладки верхнего уровня: Конфигурация / Статус (бейдж версии -> Статус) --- */

  $('ver').onclick = function (e) {
    e.preventDefault();
    if (window.susaninOpenTab) window.susaninOpenTab('status');
  };

  function loadAll() { load(); loadLists(); }

  /* Смена языка: перерисовываем всё, что собрано из строк словаря (списки,
   * статус, заголовок модалки). Ответы сервера (лог, тексты ошибок API) —
   * как их отдал агент, их перевод — отдельная задача на стороне C-кода. */
  function relabel() {
    renderLists();
    if (lastStatus) renderStatus(lastStatus);
    if (memoName) {
      $('memo-title').textContent = T('memo.titleOf', 'Список: {name}', {
        name: memoName === 'vpn_always' ? T('list.always.title', 'Всегда через VPN')
                                        : T('list.never.title', 'Всегда напрямую')
      });
      memoSetSaveEnabled(memoLoaded);
    }
  }
  document.addEventListener('susanin:lang', relabel);

  /* Высота липкой шапки в CSS-переменную: на узком экране шапка выше одной
   * строки, и жёсткий top:76px у навигации ломал вёрстку (дефект 2026-10-14). */
  (function trackTopbar() {
    var bar = document.querySelector('.topbar');
    if (!bar || !window.ResizeObserver) return;
    var apply = function () {
      document.documentElement.style.setProperty('--topbar-h', bar.offsetHeight + 'px');
    };
    new ResizeObserver(apply).observe(bar);
    apply();
  })();

  function boot() {
    loadAll();
    loadChoices();   /* один раз: подсказки для полей конфигурации (config.js) */
    /* Список НЕ переопрашиваем таймером — иначе перерисовка мешает
     * перетаскиванию; обновляется по действию и вручную ("Обновить"). */
    window.setInterval(load, 5000);
  }

  /* Рисуем только после того, как i18n применил словарь: иначе подписи и
   * пустые состояния на мгновение были бы на другом языке. */
  if (window.I18N && window.I18N.ready) window.I18N.ready(boot);
  else boot();
})();
