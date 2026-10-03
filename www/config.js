/* Susanin.Keenetic — «Конфигурация агента».
 * Разделы/подписи/группировка по темам (VPN/Egress, LAN, ...) заданы здесь —
 * это UI-разметка, её в конфиге нет. САМИ ЗНАЧЕНИЯ читаются через настоящий
 * API агента: GET /api/config -> {"file":..,"params":{key:value,...},
 * "token_set":bool}. Сохранение — POST /api/config (form-urlencoded), правит
 * только уже существующие в файле ключи; web_token через API не меняется
 * (сервер игнорирует), web_listen не может стать 0.0.0.0. Токен — тот же,
 * что app.js хранит под 'susanin_token' и шлёт заголовком X-Auth-Token. */
(function () {
  'use strict';

  var API_URL = '/api/config';

  var $ = function (id) { return document.getElementById(id); };
  var nav = $('cfgNav');
  var body = $('cfgBody');
  if (!nav || !body) return;

  var confValues = null; /* {key: value, ...} после GET /api/config; null = не прочитан */
  var tokenSet = false;

  function authToken() {
    try { return localStorage.getItem('susanin_token') || ''; } catch (e) { return ''; }
  }

  function authHeaders(extra) {
    var h = extra ? Object.assign({}, extra) : {};
    var t = authToken();
    if (t) h['X-Auth-Token'] = t;
    return h;
  }

  /* Ключа нет в загруженном конфиге — undefined (не строка), чтобы отличать
   * "нет" от легитимно пустого значения ("key="). */
  function fileValue(key) {
    if (confValues && Object.prototype.hasOwnProperty.call(confValues, key)) return confValues[key];
    return undefined;
  }

  function f(key, label, desc, type, extra) {
    var o = { key: key, label: label, desc: desc || '', type: type || 'text' };
    if (extra) for (var k in extra) o[k] = extra[k];
    return o;
  }

  var TABS = [
    {
      id: 'status', label: 'Статус', view: 'view-status', groups: []
    },
    {
      id: 'egress', label: 'VPN / Egress',
      groups: [
        { title: 'Тоннель', fields: [
          f('egress_interface', 'Интерфейс(ы) тоннеля', 'через запятую — несколько включают фейловер', 'text'),
          f('egress_address', 'Адрес(а) тоннеля', 'по индексу совпадает с интерфейсами (источник для health-проб)', 'text', { kind: 'iplist' }),
          f('egress_type', 'Тип egress', '', 'select', { options: ['interface', 'tproxy'] }),
          f('tproxy_port', 'Порт локального Xray', 'только для egress_type=tproxy', 'number', { kind: 'int' })
        ]},
        { title: 'UDP-релей (для tproxy/XRay)', fields: [
          f('udp_relay', 'UDP-релей включён', 'нужен только при egress_type=tproxy', 'bool'),
          f('udp_relay_port', 'Порт приёма (TPROXY)', '', 'number', { kind: 'int' }),
          f('socks_addr', 'Адрес Xray SOCKS', '', 'text', { kind: 'ip' }),
          f('socks_port', 'Порт Xray SOCKS', '', 'number', { kind: 'int' })
        ]},
        { title: 'Отказоустойчивость (Master/Slave)', fields: [
          f('egress_failback', 'Возврат на приоритетный VPN', 'первый в egress_interface — основной; после его восстановления трафик возвращается на него', 'bool'),
          f('egress_failback_debounce', 'Пауза до возврата', 'сек; сколько основной должен держаться, прежде чем вернуться', 'text', { kind: 'duration' }),
          f('egress_race', 'Автовыбор быстрейшего VPN', 'замерять отклик и держать трафик на самом быстром', 'bool'),
          f('egress_race_list', 'Кандидаты race', 'интерфейсы через запятую; пусто = egress_interface', 'text'),
          f('auto_direct', 'Мягкое «прямо» (авто-возврат)', 'если адрес в VPN деградирует — временно напрямую, потом обратно', 'bool'),
          f('direct_pref_ttl', 'TTL мягкого «прямо»', 'сек', 'text', { kind: 'duration' })
        ]}
      ]
    },
    {
      id: 'lan', label: 'LAN',
      groups: [
        { fields: [
          f('lan_interfaces', 'LAN-интерфейсы', 'через запятую', 'text'),
          f('lan_subnets', 'LAN-подсети', 'CIDR через запятую', 'text', { kind: 'cidrlist' }),
          f('lan_server_interfaces', 'Серверные туннели (qWDTT и т.п.)', 'их клиентов тоже обрабатываем как LAN', 'text'),
          f('discover_exclude', 'Никогда не брать как egress/LAN', '', 'text')
        ]}
      ]
    },
    {
      id: 'routing', label: 'Маршрутизация',
      groups: [
        { fields: [
          f('routing_table', 'Номер таблицы', 'должен быть небольшим (ограничение busybox ip)', 'number', { kind: 'int' }),
          f('mark_test', 'mark_test', 'fwmark, hex', 'text', { kind: 'hex' }),
          f('mark_ok', 'mark_ok', 'fwmark, hex', 'text', { kind: 'hex' }),
          f('mark_mask', 'mark_mask', 'fwmark, hex', 'text', { kind: 'hex' }),
          f('ip_rule_priority_start', 'Приоритет ip rule (старт)', '', 'number', { kind: 'int' })
        ]},
        { title: 'Kernel-offload (быстрый путь для CDN)', fields: [
          f('kernel_offload', 'Offload включён', 'адреса из ok_net идут маршрутом через интерфейс, минуя userspace-обработку', 'bool'),
          f('kernel_egress', 'Интерфейс offload', 'например nwg0; пусто = выключено', 'text'),
          f('kernel_offload_max', 'Макс. длина префикса', 'бит; шире — не агрегировать', 'number', { kind: 'int' })
        ]},
        { title: 'MSS/PMTU (если сайты через VPN зависают)', fields: [
          f('mss_clamp', 'Ограничить размер пакета', '0 = выкл; число байт (напр. 1380) или pmtu', 'text'),
          f('mss_clamp_lan', 'Применять ко всему LAN', 'выкл — только к помеченному VPN-трафику', 'bool')
        ]}
      ]
    },
    {
      id: 'timers', label: 'Таймеры и кэш',
      groups: [
        { title: 'Опрос', fields: [
          f('fast_interval', 'fast_interval', 'сек; «быстрая» фаза детекта', 'text', { kind: 'duration' }),
          f('soft_interval', 'soft_interval', 'сек; «мягкая» фаза (потоки с ответами)', 'text', { kind: 'duration' }),
          f('judge_interval', 'judge_interval', 'сек; фаза подтверждения (judge)', 'text', { kind: 'duration' }),
          f('health_interval', 'health_interval', 'сек; интервал health-проб тоннеля', 'text', { kind: 'duration' }),
          f('dp_check_interval', 'Сверка датаплейна (reconcile)', 'сек; 0 = 15', 'text', { kind: 'duration' }),
          f('fast_syn_min_op', 'SYN без ответа до детекта', 'число SYN; меньше = быстрее, но больше ложных срабатываний', 'number', { kind: 'int' })
        ]},
        { title: 'Кэш (TTL)', fields: [
          f('ok_ttl', 'ok_ttl', 'сек; 0 = никогда не истекает', 'number', { kind: 'int' }),
          f('ok_refresh_below', 'ok_refresh_below', 'ч; обновлять ok-адрес, если до истечения меньше', 'text', { kind: 'duration' }),
          f('ok_max_entries', 'ok_max_entries', 'лимит записей на протокол; 0 = без лимита', 'number', { kind: 'int' }),
          f('promo_per_min', 'promo_per_min', 'лимит новых переводов в VPN в минуту; 0 = без лимита', 'number', { kind: 'int' }),
          f('ok_evict_misses', 'ok_evict_misses', 'сколько подряд сбоев для снятия из ok (1 = сразу)', 'number', { kind: 'int' }),
          f('test_ttl', 'test_ttl', 'мин; TTL «test»-состояния (проба через VPN)', 'text', { kind: 'duration' }),
          f('cooldown_ttl', 'cooldown_ttl', 'мин; «остывание» после снятия из ok', 'text', { kind: 'duration' }),
          f('cooldown_ok_ttl', 'cooldown_ok_ttl', 'сек; «остывание» подтверждённого адреса', 'text', { kind: 'duration' }),
          f('watch_ttl', 'watch_ttl', 'сек; TTL «наблюдения» за подозрительным потоком', 'text', { kind: 'duration' }),
          f('watch_retry_below', 'watch_retry_below', 'сек; мин. время до повторной пробы', 'text', { kind: 'duration' })
        ]}
      ]
    },
    {
      id: 'health', label: 'Health-проверка',
      groups: [
        { fields: [
          f('health_probe', 'Адреса проверки тоннеля', 'через запятую; источник пробы — адрес тоннеля (egress_address)', 'text', { kind: 'iplist' }),
          f('health_miss_debounce', 'Порог «тоннель упал»', 'подряд неудачных проб', 'number', { kind: 'int' }),
          f('health_mode', 'Тип пробы', 'tcp — если тоннель не несёт ICMP (напр. XRay/TUN)', 'select', { options: ['icmp', 'tcp'] }),
          f('health_tcp_port', 'Порт TCP-пробы', 'только для health_mode=tcp', 'number', { kind: 'int' })
        ]}
      ]
    },
    {
      id: 'lists', label: 'Списки VPN',
      groups: [
        { fields: [
          f('vpn_always_interval', 'Период обновления «всегда через VPN»', 'сек', 'text', { kind: 'duration' }),
          f('vpn_always_dns', 'Резолвер для списка', 'пусто = авто (роутер/LAN-мост)', 'text', { kind: 'ip' }),
          f('vpn_never_interval', 'Период обновления «всегда напрямую»', 'сек', 'text', { kind: 'duration' }),
          f('pin_reassert', 'Самолечение пинов списков', 'периодически передобавлять адреса «всегда через VPN» (восстанавливать потерянные)', 'bool')
        ]}
      ],
      note: 'Сами домены/IP редактируются в разделе «Списки маршрутизации» ниже (перетаскиванием). Здесь — только настройки периода/резолвера для этих списков.'
    },
    {
      id: 'learn', label: 'Обучение',
      groups: [
        { fields: [
          f('learn_min_op', 'learn_min_op', 'мин. пакетов к адресу для обучения', 'number', { kind: 'int' }),
          f('learn_min_bytes', 'learn_min_bytes', 'мин. байт «от нас»', 'number', { kind: 'int' }),
          f('confirm_min_bytes', 'confirm_min_bytes', 'мин. ответных байт для подтверждения', 'number', { kind: 'int' }),
          f('learn_strict', 'learn_strict', 'удвоить пороги (ещё строже)', 'bool'),
          f('learn_exclude_ports', 'Порты без быстрого автообучения', 'через запятую — типовой шум сканов', 'text', { kind: 'intlist' })
        ]}
      ]
    },
    {
      id: 'cdn', label: 'CDN',
      groups: [
        { fields: [
          f('cdn_ranges_url', 'Источник диапазонов CDN', '', 'text'),
          f('cdn_ranges_interval', 'Период обновления', 'секунд; 0 = не обновлять', 'number', { kind: 'int' }),
          f('cdn_prefix_learn', 'Агрегация по префиксу', '', 'bool'),
          f('cdn_prefix_ttl', 'TTL агрегированного префикса', 'секунд', 'number', { kind: 'int' }),
          f('cdn_prefix_max', 'Не агрегировать шире', 'бит маски (/24 по умолчанию)', 'number', { kind: 'int' })
        ]}
      ]
    },
    {
      id: 'block', label: 'Блокировки',
      groups: [
        { fields: [
          f('ipv6_block', 'Блокировать IPv6 для LAN', 'чтобы клиенты уходили на IPv4', 'bool'),
          f('quic_block', 'Блокировать QUIC (UDP/443)', 'иначе приложения зависают в ожидании QUIC', 'bool')
        ]}
      ]
    },
    {
      id: 'xray', label: 'Xray и DNS',
      groups: [
        { title: 'Xray (память и watchdog)', fields: [
          f('xray_watchdog', 'Самоподъём упавшего Xray', 'агент сам перезапускает Xray при падении (режим tproxy)', 'bool'),
          f('xray_gogc', 'GOGC (чаще уборка мусора)', 'меньше = агрессивнее; пусто = по умолчанию Go', 'text'),
          f('xray_gomemlimit', 'Лимит памяти', 'мягкий лимит, напр. 64MiB', 'text')
        ]},
        { title: 'DNS-снифинг (домен → IP)', fields: [
          f('dns_sniff', 'Снифинг включён', 'зеркально смотреть DNS-ответы; штатный DNS не трогается', 'bool'),
          f('dns_sniff_ttl', 'TTL записи', 'сек', 'text', { kind: 'duration' }),
          f('dns_sniff_iface', 'Интерфейс захвата', 'пусто = первый lan_interface', 'text')
        ]}
      ],
      note: 'DNS-снифинг помогает точнее заворачивать домены из списков вместе с поддоменами (по умолчанию выключен).'
    },
    {
      id: 'media', label: 'Медиа (IPTV)',
      groups: [
        { fields: [
          f('media_enabled', 'Класс media включён', 'детект IPTV/видео по форме потока и увод серверов в VPN', 'bool'),
          f('media_ports', 'Порты media', 'через запятую: 80,443,554,1935,8080', 'text'),
          f('media_min_bytes', 'Мин. байт ответа', 'напр. 1048576', 'number', { kind: 'int' }),
          f('media_ratio', 'Отношение rb/ob', 'напр. 8', 'number', { kind: 'int' }),
          f('media_min_rate', 'Мин. скорость, Б/с', 'напр. 150000', 'number', { kind: 'int' }),
          f('media_min_age', 'Мин. возраст, сек', 'напр. 12', 'text', { kind: 'duration' }),
          f('media_ttl', 'TTL префикса, сек', 'напр. 21600', 'text', { kind: 'duration' }),
          f('media_prefix_max', 'Макс. префикс', 'напр. 24', 'number', { kind: 'int' })
        ]}
      ],
      note: 'Media-класс (IPTV/видео): увидев крупный асимметричный поток, агент пинит ближайший префикс в VPN — последующие потоки идут через VPN с первого пакета (без FASTNAT-залипаний). По умолчанию выключен.'
    },
    {
      id: 'web', label: 'Диагностика и Web',
      groups: [
        { title: 'Диагностика', fields: [
          f('log_level', 'log_level', '', 'select', { options: ['quiet', 'error', 'warn', 'info', 'debug', 'trace'] }),
          f('xray_loglevel', 'xray_loglevel', 'отдельно от log_level агента', 'select', { options: ['debug', 'info', 'warning', 'none'] }),
          f('disk_mode', 'disk_mode', 'soft — минимум записей на носитель (NAND)', 'select', { options: ['normal', 'soft'] }),
          f('soft_state_interval', 'soft_state_interval', 'ч; 0 = никогда (период сохранения состояния в soft-режиме)', 'text', { kind: 'duration' })
        ]},
        { title: 'Веб-панель', fields: [
          f('web_enable', 'Веб-панель включена', '', 'bool'),
          f('web_listen', 'Адрес (LAN)', 'не 0.0.0.0', 'text', { kind: 'ip', noZero: true }),
          f('web_port', 'Порт', '', 'number', { kind: 'int' }),
          f('web_token', 'Токен доступа', 'пусто = оставить как есть; «Сбросить» — снять токен', 'token')
        ]}
      ]
    },
    {
      id: 'profiles', label: 'Профили',
      groups: [
        { title: 'Общие', fields: [
          f('profile_failover', 'Держать профиль на рабочем VPN', 'следить, чтобы таблица профиля указывала на первый живой egress из списка', 'bool')
        ]}
      ].concat([1, 2, 3, 4].map(function (n) {
        var p = 'profile' + n + '_';
        return { title: 'Профиль ' + n, fields: [
          f(p + 'name', 'Имя', 'a-z, 0-9, _ ; пусто = профиль выключен', 'text', { kind: 'ident', creatable: true }),
          f(p + 'egress', 'Egress (туннель)', 'интерфейс или список через запятую (первый живой)', 'text', { creatable: true }),
          f(p + 'list', 'Файл списка', 'путь, например /opt/susanin/etc/profiles/имя.txt (по строке: домен / IP / CIDR)', 'text', { creatable: true }),
          f(p + 'geo_url', 'Ссылка на список (гео)', 'скачиваемый CIDR-список; кэш в var/profiles/', 'text', { creatable: true }),
          f(p + 'auto', 'Автообучение профиля', 'пополнять профиль новыми адресами из его диапазона', 'bool', { creatable: true }),
          f(p + 'table', 'Таблица маршрутизации', 'пусто = по умолчанию (201…204)', 'number', { kind: 'int', creatable: true }),
          f(p + 'mark', 'fwmark', 'hex; пусто = по умолчанию', 'text', { kind: 'hex', creatable: true })
        ]};
      })),
      note: 'Профили: свой список доменов/IP на отдельный туннель, со своей меткой и таблицей. ' +
        'Профиль включается при заданном имени; можно задавать и файлом /opt/susanin/etc/profiles.d/<имя>.conf. ' +
        'Применяется после Reload/Restart (sh /opt/susanin/tools/profiles.sh up), списки — profiles.sh refresh.'
    }
  ];

  /* --- валидация ввода по "виду" поля (kind) ------------------------- */

  var KIND_CHARS = {
    int: /[0-9]/,
    ip: /[0-9.]/,
    iplist: /[0-9., ]/,
    hex: /[0-9a-fA-Fx]/,
    duration: /[0-9]/,
    cidrlist: /[0-9./, ]/,
    intlist: /[0-9, ]/,
    ident: /[a-z0-9_]/
  };

  function filterValue(kind, value) {
    var re = KIND_CHARS[kind];
    if (!re) return value;
    var out = '';
    for (var i = 0; i < value.length; i++) {
      if (re.test(value[i])) out += value[i];
    }
    return out;
  }

  function isValidIPv4(s) {
    var parts = s.split('.');
    if (parts.length !== 4) return false;
    return parts.every(function (p) {
      if (!/^[0-9]{1,3}$/.test(p)) return false;
      var n = +p;
      return n >= 0 && n <= 255;
    });
  }

  function isValidFormat(fld, value) {
    if (!value) return true;
    if (fld.noZero && value === '0.0.0.0') return false;
    switch (fld.kind) {
      case 'int': return /^[0-9]+$/.test(value);
      case 'ip': return isValidIPv4(value);
      case 'iplist': return value.split(',').every(function (s) { s = s.trim(); return !!s && isValidIPv4(s); });
      case 'hex': return /^0x[0-9a-fA-F]+$/.test(value);
      case 'duration': return /^[0-9]+$/.test(value);
      case 'cidrlist': return value.split(',').every(function (s) {
        s = s.trim();
        var m = s.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
        return !!m && isValidIPv4(m[1]) && +m[2] <= 32;
      });
      case 'ident': return /^[a-z0-9_]+$/.test(value);
      case 'intlist': return value.split(',').every(function (s) { s = s.trim(); return /^[0-9]+$/.test(s); });
      default: return true;
    }
  }

  function attachValidation(inp, fld) {
    function check() { inp.classList.toggle('invalid', !isValidFormat(fld, inp.value)); }
    inp.addEventListener('input', function () {
      var filtered = fld.kind ? filterValue(fld.kind, inp.value) : inp.value;
      if (filtered !== inp.value) {
        var pos = inp.selectionStart - (inp.value.length - filtered.length);
        inp.value = filtered;
        try { inp.setSelectionRange(pos, pos); } catch (e) {}
      }
      check();
    });
    inp.addEventListener('blur', check);
  }

  function toast(msg, ok) {
    var box = $('toast');
    if (!box) return;
    var el = document.createElement('div');
    el.className = 'msg' + (ok === false ? ' err' : '');
    el.textContent = msg;
    box.appendChild(el);
    window.setTimeout(function () { el.remove(); }, 3000);
  }

  /* confValues === null — конфиг вообще не прочитан (запрос упал/401/etc);
   * confValues — объект, но ключа нет — прочитан, просто нет такой строки в
   * файле (новые ключи через API не создаются, поэтому поле недоступно). */
  function missingLabel() {
    return confValues === null ? 'конфиг не прочитан' : 'нет в файле';
  }

  function missingTag() {
    var tag = document.createElement('span');
    tag.className = 'muted';
    tag.style.fontSize = '11px';
    tag.style.marginLeft = '8px';
    tag.textContent = missingLabel();
    return tag;
  }

  function fieldRow(fld) {
    var wrap = document.createElement('div');
    wrap.className = 'cfg-field';

    var lbl = document.createElement('div');
    lbl.className = 'lbl';
    var b = document.createElement('b');
    b.textContent = fld.label;
    var key = document.createElement('span');
    key.className = 'key';
    key.textContent = fld.key;
    lbl.appendChild(b);
    lbl.appendChild(key);
    wrap.appendChild(lbl);

    if (fld.desc) {
      var d = document.createElement('div');
      d.className = 'desc';
      d.textContent = fld.desc;
      wrap.appendChild(d);
    }

    if (fld.type === 'readonly') {
      var ro = document.createElement('div');
      ro.className = 'desc';
      ro.textContent = tokenSet ? 'токен задан (значение скрыто)' : 'токен не задан — доступ без пароля';
      wrap.appendChild(ro);
      return wrap;
    }

    if (fld.type === 'token') {
      /* web_token: значение write-only (GET его не отдаёт). Пустое поле =
       * «не менять»; «Сбросить» = снять токен (сохранить web_token=). */
      var tinp = document.createElement('input');
      tinp.type = 'password';
      tinp.dataset.key = fld.key;
      tinp.autocomplete = 'new-password';
      tinp.placeholder = tokenSet ? '(задан — оставьте пустым, чтобы не менять)'
                                  : '(пусто — доступ без пароля)';
      wrap.appendChild(tinp);
      var tclr = document.createElement('button');
      tclr.type = 'button';
      tclr.className = 'btn btn-sm';
      tclr.textContent = 'Сбросить';
      tclr.title = 'Снять токен (сохранить web_token=)';
      tclr.onclick = function () {
        tinp.value = '';
        tinp.dataset.clear = '1';
        toast('Токен будет снят после «Сохранить раздел»', true);
      };
      wrap.appendChild(tclr);
      return wrap;
    }

    var raw = fileValue(fld.key);
    var present = raw !== undefined;
    var val = present ? raw : '';

    if (fld.type === 'bool') {
      var sw = document.createElement('label');
      sw.className = 'switch';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = val === '1';
      cb.dataset.key = fld.key;
      if (!present) cb.disabled = true;
      var track = document.createElement('span');
      track.className = 'track';
      var thumb = document.createElement('span');
      thumb.className = 'thumb';
      track.appendChild(thumb);
      sw.appendChild(cb);
      sw.appendChild(track);
      wrap.appendChild(sw);
      if (!present) wrap.appendChild(missingTag());
    } else if (fld.type === 'select') {
      var sel = document.createElement('select');
      sel.dataset.key = fld.key;
      if (!present) {
        var placeholderOpt = document.createElement('option');
        placeholderOpt.value = '';
        placeholderOpt.textContent = '— ' + missingLabel() + ' —';
        placeholderOpt.selected = true;
        placeholderOpt.disabled = true;
        sel.appendChild(placeholderOpt);
        sel.disabled = true;
      }
      (fld.options || []).forEach(function (opt) {
        var o = document.createElement('option');
        o.value = opt;
        o.textContent = opt;
        if (present && opt === val) o.selected = true;
        sel.appendChild(o);
      });
      if (present && (fld.options || []).indexOf(val) < 0) {
        var custom = document.createElement('option');
        custom.value = val;
        custom.textContent = val + ' (нет в списке)';
        custom.selected = true;
        sel.appendChild(custom);
      }
      wrap.appendChild(sel);
    } else {
      var inp = document.createElement('input');
      inp.type = fld.type === 'password' ? 'password' : (fld.type === 'number' ? 'number' : 'text');
      inp.dataset.key = fld.key;
      if (val) inp.value = val;
      else inp.placeholder = present ? '(пусто)' : (fld.creatable ? 'будет создано при сохранении' : '(' + missingLabel() + ')');
      if (!present && !fld.creatable) inp.disabled = true; /* creatable — можно задать и создать */
      if (fld.kind || fld.noZero) attachValidation(inp, fld);
      wrap.appendChild(inp);
      if (!present && !fld.creatable) wrap.appendChild(missingTag());
    }

    return wrap;
  }

  function saveTab(tab, bodyEl) {
    var pairs = [];
    var invalidField = null, n = 0;
    var newToken = null, clearToken = false;

    function push(key, val) { pairs.push([key, val]); n++; }

    tab.groups.forEach(function (g) {
      /* Профиль: сохраняем группу, только если задано имя ИЛИ профиль уже есть
       * в файле (иначе пустые блоки profileN_* не создаём). */
      if (g.fields.length && /^profile[1-4]_name$/.test(g.fields[0].key)) {
        var nl = bodyEl.querySelector('[data-key="' + g.fields[0].key + '"]');
        var nv = nl ? nl.value.trim() : '';
        var anyPresent = g.fields.some(function (fld) { return fileValue(fld.key) !== undefined; });
        if (!nv && !anyPresent) return;
      }

      g.fields.forEach(function (fld) {
        var el = bodyEl.querySelector('[data-key="' + fld.key + '"]');
        if (!el) return;
        if (fld.type === 'token') {
          if (el.value) { push(fld.key, el.value); newToken = el.value; }
          else if (el.dataset.clear === '1') { push(fld.key, ''); clearToken = true; }
          return;
        }
        if (fld.type === 'readonly') return;
        if (el.disabled) return; /* нет в файле и не creatable — нечего сохранять */
        if (el.classList && el.classList.contains('invalid')) { invalidField = fld; return; }
        push(fld.key, el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value);
      });
    });

    if (invalidField) {
      toast('Проверьте формат поля «' + invalidField.label + '»', false);
      return;
    }
    if (!n) {
      toast('Нечего сохранять — все поля раздела пустые/отсутствуют в файле', false);
      return;
    }

    var body = new URLSearchParams();
    pairs.forEach(function (p) { body.append(p[0], p[1]); });

    fetch(API_URL, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: body.toString()
    }).then(function (r) { return r.json(); }).then(function (r) {
      if (r && r.ok) {
        /* web_token — write-only: после смены запоминаем/снимаем локально,
         * иначе следующий же запрос уйдёт со старым токеном. */
        try {
          if (newToken) localStorage.setItem('susanin_token', newToken);
          else if (clearToken) localStorage.removeItem('susanin_token');
        } catch (e) {}
        toast('Сохранено, конфиг перечитан агентом (SIGHUP)', true);
        return loadConfig();
      }
      toast('Ошибка сохранения: ' + ((r && r.error) || 'неизвестно'), false);
    }).catch(function (e) {
      toast('Ошибка сохранения: ' + e.message, false);
    });
  }

  /* Закладка со своим готовым блоком (view): блок живёт в index.html, при
   * смене закладки возвращается в скрытый контейнер, чтобы не потерять обработчики. */
  var statusEl = $('view-status');
  var statusHome = statusEl ? statusEl.parentNode : null;

  function renderPane(tab) {
    if (statusEl) { statusEl.hidden = true; statusHome.appendChild(statusEl); }
    body.innerHTML = '';

    var head = document.createElement('div');
    head.className = 'cfg-pane-head';

    var title = document.createElement('div');
    title.className = 'cfg-pane-title';
    title.textContent = tab.label;
    head.appendChild(title);

    if (!confValues) {
      var err = document.createElement('span');
      err.className = 'cfg-pane-note err';
      err.textContent = 'не удалось прочитать конфиг';
      head.appendChild(err);
    }

    body.appendChild(head);

    if (tab.view && statusEl) {
      statusEl.hidden = false;
      body.appendChild(statusEl);
      return;
    }

    if (tab.note) {
      var note = document.createElement('div');
      note.className = 'cfg-pane-extra';
      note.textContent = tab.note;
      body.appendChild(note);
    }

    if (tab.placeholder) {
      var ph = document.createElement('div');
      ph.className = 'cfg-placeholder';
      ph.textContent = tab.placeholder;
      body.appendChild(ph);
      return;
    }

    tab.groups.forEach(function (g) {
      var group = document.createElement('div');
      group.className = 'cfg-group';
      if (g.title) {
        var gt = document.createElement('div');
        gt.className = 'cfg-group-title';
        gt.textContent = g.title;
        group.appendChild(gt);
      }
      g.fields.forEach(function (fld) { group.appendChild(fieldRow(fld)); });
      body.appendChild(group);
    });

    var save = document.createElement('div');
    save.className = 'cfg-save';
    var btn = document.createElement('button');
    btn.className = 'btn btn-outline';
    btn.textContent = 'Сохранить раздел';
    btn.title = 'POST /api/config — правит только поля, у которых есть значение в файле';
    btn.onclick = function () { saveTab(tab, body); };
    var hint = document.createElement('span');
    hint.className = 'muted';
    hint.style.fontSize = '12px';
    hint.textContent = 'сохраняются только поля, присутствующие в текущем конфиге';
    save.appendChild(btn);
    save.appendChild(hint);
    body.appendChild(save);
  }

  var activeTabId = TABS[0].id;

  function selectTab(id) {
    activeTabId = id;
    Array.prototype.forEach.call(nav.children, function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === id);
    });
    var tab = TABS.filter(function (t) { return t.id === id; })[0];
    if (tab) renderPane(tab);
  }

  TABS.forEach(function (tab, i) {
    var btn = document.createElement('button');
    btn.className = 'cfg-tab' + (i === 0 ? ' active' : '');
    btn.setAttribute('data-tab', tab.id);
    btn.textContent = tab.label;
    btn.onclick = function () { selectTab(tab.id); };
    nav.appendChild(btn);
  });

  function loadConfig() {
    return fetch(API_URL, { cache: 'no-store', headers: authHeaders() }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (data) {
      confValues = data.params || {};
      tokenSet = !!data.token_set;
    }).catch(function () {
      confValues = null;
      tokenSet = false;
    }).then(function () {
      selectTab(activeTabId);
    });
  }

  window.susaninOpenTab = selectTab;
  if (window.location.hash === '#status') selectTab('status');

  loadConfig();
})();
