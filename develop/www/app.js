/* Susanin.Keenetic — веб-панель (W2/W3, без внешних зависимостей).
 * Данные: GET /api/status, GET /api/log. Токен хранится в localStorage и
 * передаётся заголовком X-Auth-Token (либо один раз через ?token=...). */
(function () {
  'use strict';

  var TOKEN_KEY = 'susanin_token';
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

  $('token').value = token;
  $('save').onclick = function () {
    token = $('token').value.trim();
    try { localStorage.setItem(TOKEN_KEY, token); } catch (e) {}
    load();
  };
  $('refresh').onclick = load;

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

  function act(msg, ok) {
    var el = $('act');
    el.textContent = msg;
    el.className = ok ? 'muted' : 'err';
  }

  function doPost(path, params, label) {
    act(label + '…', true);
    post(path, params).then(function (r) {
      if (r && r.ok) { act(label + ': ok', true); load(); }
      else act(label + ': ' + ((r && r.error) || 'ошибка'), false);
    }).catch(function (e) { act(label + ': ' + e.message, false); });
  }

  $('reload').onclick = function () { doPost('/api/reload', {}, 'reload'); };
  $('rescan').onclick = function () { doPost('/api/rescan', {}, 'rescan'); };
  $('restart').onclick = function () { doPost('/api/restart', {}, 'restart'); };
  $('forget').onclick = function () {
    var ip = $('fip').value.trim();
    if (!ip) { act('forget: укажите IP', false); return; }
    doPost('/api/forget', { ip: ip }, 'forget ' + ip);
  };
  $('ladd').onclick = function () {
    var v = $('lval').value.trim();
    if (!v) { act('укажите значение', false); return; }
    doPost('/api/list', { list: $('lname').value, op: 'add', value: v }, 'add ' + v);
  };
  $('ldel').onclick = function () {
    var v = $('lval').value.trim();
    if (!v) { act('укажите значение', false); return; }
    doPost('/api/list', { list: $('lname').value, op: 'del', value: v }, 'del ' + v);
  };

  function card(k, v) {
    return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div></div>';
  }

  function renderStatus(d) {
    $('ver').textContent = 'v' + d.version;
    var e = d.egress || {};
    $('cards').innerHTML =
      card('Egress', (e.interface || '—') + ' (' + (e.count || 0) + ')') +
      card('Тип egress', e.type || 'interface') +
      card('Таблица', e.table) +
      card('LAN', e.lan_interfaces || '—') +
      card('Подсети', e.lan_subnets || '—') +
      card('Mark test / ok', (e.mark_test || '—') + ' / ' + (e.mark_ok || '—')) +
      card('Профили', (d.profiles || []).length) +
      card('Состояние (state)', d.state_file ? 'есть' : 'нет') +
      card('Web', d.web && d.web.enable ? 'включён' : 'выключен');

    var tb = document.querySelector('#sets tbody');
    tb.innerHTML = '';
    var ipsets = d.ipsets || {};
    Object.keys(ipsets).forEach(function (k) {
      tb.insertAdjacentHTML('beforeend',
        '<tr><td>' + esc(k) + '</td><td>' + esc(ipsets[k]) + '</td></tr>');
    });

    var lb = document.querySelector('#lists tbody');
    lb.innerHTML = '';
    ['vpn_always', 'vpn_never'].forEach(function (name) {
      var o = (d.lists || {})[name] || {};
      var cnt = (o.count < 0 ? 'нет файла' : o.count);
      lb.insertAdjacentHTML('beforeend',
        '<tr><td>' + esc(name) + '</td><td>' + esc(cnt) + '</td><td>' + esc(o.file || '') + '</td></tr>');
    });
  }

  function load() {
    api('/api/status').then(function (t) {
      var d;
      try { d = JSON.parse(t); } catch (e) { throw new Error('bad JSON'); }
      renderStatus(d);
    }).catch(function (e) {
      $('cards').innerHTML = '<div class="err">Ошибка: ' + esc(e.message) + '</div>';
    });

    api('/api/log?lines=200').then(function (t) {
      var el = $('log');
      el.textContent = t || '(пусто)';
      el.scrollTop = el.scrollHeight;
    }).catch(function () { /* лог не критичен */ });
  }

  load();
  window.setInterval(load, 5000);
})();
