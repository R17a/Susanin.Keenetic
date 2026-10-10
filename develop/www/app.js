/* Susanin.Keenetic — веб-панель (W2/W3, без внешних зависимостей).
 * Данные: GET /api/status, GET /api/list?name=..., GET /api/log. Токен хранится
 * в localStorage и передаётся заголовком X-Auth-Token (либо один раз через
 * ?token=...). Списки vpn_always/vpn_never редактируются перетаскиванием между
 * колонками (или стрелкой на записи — для touch-устройств). */
(function () {
  'use strict';

  var TOKEN_KEY = 'susanin_token';
  var LISTS = ['vpn_always', 'vpn_never'];
  var LIST_LABEL = { vpn_always: 'через VPN', vpn_never: 'напрямую' };

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


  function api(path) {
    var headers = {};
    if (token) headers['X-Auth-Token'] = token;
    return fetch(path, { headers: headers, cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
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
      return r.json();
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

  function setConn(ok) {
    var d = $('dot');
    d.className = 'dot ' + (ok ? 'ok' : 'err');
  }

  function doPost(path, params, label) {
    return post(path, params).then(function (r) {
      if (r && r.ok) { toast(label + ': ок', true); return true; }
      toast(label + ': ' + ((r && r.error) || 'ошибка'), false);
      return false;
    }).catch(function (e) { toast(label + ': ' + e.message, false); return false; });
  }

  $('reload').onclick = function () { doPost('/api/reload', {}, 'reload').then(loadAll); };
  $('rescan').onclick = function () { doPost('/api/rescan', {}, 'rescan').then(loadAll); };
  $('restart').onclick = function () { doPost('/api/restart', {}, 'restart').then(loadAll); };
  $('reset').onclick = function () {
    var ip = $('fip').value.trim();
    if (!ip) { toast('reset: укажите IP или домен', false); return; }
    doPost('/api/reset', { ip: ip }, 'reset ' + ip);
  };

  function renderStatus(d) {
    $('ver').textContent = 'v' + d.version;
    var tb = document.querySelector('#sets tbody');
    tb.innerHTML = '';
    var ipsets = d.ipsets || {};
    Object.keys(ipsets).forEach(function (k) {
      tb.insertAdjacentHTML('beforeend',
        '<tr><td>' + esc(k) + '</td><td>' + esc(ipsets[k]) + '</td></tr>');
    });
  }

  function load() {
    api('/api/status').then(function (t) {
      var d;
      try { d = JSON.parse(t); } catch (e) { throw new Error('bad JSON'); }
      renderStatus(d);
      setConn(true);
    }).catch(function () {
      setConn(false);
    });

    api('/api/log?lines=200').then(function (t) {
      var el = $('log');
      el.textContent = t || '(пусто)';
      el.scrollTop = el.scrollHeight;
    }).catch(function () { /* лог не критичен */ });
  }

  /* --- Списки vpn_always / vpn_never: drag & drop между колонками --- */

  var lists = { vpn_always: [], vpn_never: [] };
  var filters = { vpn_always: '', vpn_never: '' };
  var listErrors = { vpn_always: null, vpn_never: null };

  function fetchList(name) {
    return api('/api/list?name=' + name).then(function (t) {
      listErrors[name] = null;
      try { return JSON.parse(t); } catch (e) { listErrors[name] = 'bad JSON'; return null; }
    }).catch(function (e) {
      listErrors[name] = e.message || 'ошибка';
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
        box.innerHTML = '<div class="list-empty err">не удалось загрузить: ' + esc(listErrors[name]) + '</div>';
        return;
      }
      if (!items.length) {
        box.innerHTML = '<div class="list-empty">' +
          (lists[name].length ? 'ничего не найдено' : 'список пуст') + '</div>';
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
    move.title = 'Переместить в «' + LIST_LABEL[otherList(name)] + '»';
    move.textContent = name === 'vpn_always' ? '→' : '←';
    move.onclick = function () { moveEntry(value, name, otherList(name)); };
    row.appendChild(move);

    var del = document.createElement('button');
    del.className = 'btn-icon del';
    del.title = 'Удалить из списка';
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
      doPost('/api/list', { list: name, op: 'add', value: v }, 'добавить ' + v)
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
      doPost('/api/list', { list: name, op: 'add', value: v }, 'добавить ' + v)
        .then(function (ok) { if (ok) { input.value = ''; loadLists(); } });
    });
  });

  function deleteEntry(value, from) {
    doPost('/api/list', { list: from, op: 'del', value: value }, 'удалить ' + value)
      .then(function (ok) { if (ok) loadLists(); });
  }

  function moveEntry(value, from, to) {
    doPost('/api/list', { list: from, op: 'del', value: value }, 'del ' + value).then(function (ok) {
      if (!ok) return;
      doPost('/api/list', { list: to, op: 'add', value: value }, 'add ' + value).then(function (ok2) {
        if (ok2) toast(value + ' → ' + LIST_LABEL[to], true);
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
    $('memo-save').title = on ? 'Записать весь список' : 'Сначала дождитесь загрузки списка';
    $('memo-text').readOnly = !on;
  }

  /* Читаемая ошибка вместо «Unexpected token» при текстовом ответе (401/413/400). */
  function httpError(r) {
    return r.text().then(function (t) {
      var msg = (t || '').trim();
      if (r.status === 401) msg = 'нужен токен (обновите страницу с ?token=…)';
      else if (r.status === 413) msg = 'список больше 64 КБ — правьте его на роутере';
      else if (!msg) msg = 'HTTP ' + r.status;
      return { ok: false, error: msg };
    }).catch(function () { return { ok: false, error: 'HTTP ' + r.status }; });
  }

  function memoOpen(name) {
    memoName = name;
    memoSetSaveEnabled(false);
    $('memo-title').textContent = 'Список: ' +
      (name === 'vpn_always' ? 'Всегда через VPN' : 'Всегда напрямую');
    $('memo-status').textContent = 'загрузка…';
    $('memo-text').value = '';
    $('memo').hidden = false;
    api('/api/list/raw?name=' + encodeURIComponent(name)).then(function (t) {
      if (memoName !== name) return;
      $('memo-text').value = t;
      var n = t.split('\n').filter(function (l) { return l.trim() && l.trim()[0] !== '#'; }).length;
      $('memo-status').textContent = 'загружено записей: ' + n;
      memoSetSaveEnabled(true);
      $('memo-text').focus();
    }).catch(function (e) {
      /* Сохранение остаётся заблокированным: не даём стереть список сбоем загрузки. */
      memoSetSaveEnabled(false);
      $('memo-status').textContent = 'не удалось загрузить: ' + (e.message || 'ошибка') +
        ' — сохранение отключено';
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
    $('memo-status').textContent = 'сохранение…';
    $('memo-save').disabled = true;
    fetch('/api/list/save?name=' + encodeURIComponent(name), {
      method: 'POST', headers: headers, body: text
    }).then(function (r) {
      if (r.ok) return r.json().catch(function () { return { ok: false, error: 'плохой ответ сервера' }; });
      return httpError(r);
    }).then(function (r) {
      $('memo-save').disabled = false;
      if (!r || !r.ok) {
        $('memo-status').textContent = 'ошибка: ' + ((r && r.error) || 'не сохранено');
        toast('список не сохранён', false);
        return;
      }
      var msg = 'сохранено записей: ' + r.kept;
      if (r.dropped) msg += ', отброшено строк: ' + r.dropped;
      $('memo-status').textContent = msg;
      toast(name + ': ' + msg, !r.dropped);
      memoClose();
      loadLists();
    }).catch(function (e) {
      $('memo-save').disabled = false;
      $('memo-status').textContent = 'ошибка: ' + (e.message || e);
      toast('список не сохранён', false);
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

  loadAll();
  /* Список НЕ переопрашиваем таймером — иначе перерисовка мешает
   * перетаскиванию; обновляется по действию и вручную ("Обновить"). */
  window.setInterval(load, 5000);
})();
