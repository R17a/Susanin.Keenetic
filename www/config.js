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
    /* bool — всегда 0/1: такой ключ безопасно создать, если его нет в конфиге. */
    if (o.type === 'bool') o.creatable = true;
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
          f('egress_interface', 'Интерфейс(ы) тоннеля', 'через запятую; порядок = приоритет фейловера — перетаскивайте чипы или ← / →', 'text', { kind: 'ifacelist' }),
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
          f('auto_direct', 'Мягкое «прямо» (авто-возврат)', 'если адрес в VPN деградирует — временно напрямую, потом обратно', 'bool'),
          f('direct_pref_ttl', 'TTL мягкого «прямо»', 'сек', 'text', { kind: 'duration' })
        ]}
      ]
    },
    {
      id: 'lan', label: 'LAN',
      groups: [
        { fields: [
          f('lan_interfaces', 'LAN-интерфейсы', 'через запятую; порядок = приоритет — перетаскивайте чипы или ← / →', 'text', { kind: 'ifacelist' }),
          f('lan_subnets', 'LAN-подсети', 'CIDR через запятую', 'text', { kind: 'cidrlist' }),
          f('lan_server_interfaces', 'Серверные туннели (qWDTT и т.п.)', 'их клиентов тоже обрабатываем как LAN', 'text', { kind: 'ifacelist' }),
          f('discover_exclude', 'Никогда не брать как egress/LAN', 'интерфейсы через запятую', 'text', { kind: 'ifacelist' })
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
          f('kernel_egress', 'Интерфейс offload', 'например nwg0; пусто = выключено', 'text', { kind: 'iface' }),
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
          f('precision', 'precision', 'пресет порогов: strict | normal | aggressive (пусто = выкл); ключи выше сильнее', 'text'),
          f('port_aware', 'port_aware', 'экспериментально: решения по паре адрес+порт (нужен restart; больше памяти)', 'text'),
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
          f('cdn_prefix_max', 'Не агрегировать шире', 'бит маски (/24 по умолчанию)', 'number', { kind: 'int' }),
          f('aggregate_confirm', 'Подтверждений до агрегации', 'сколько разных адресов префикса увидеть (1 = по первому)', 'number', { kind: 'int' })
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
          f('dns_sniff_iface', 'Интерфейс захвата', 'пусто = все lan_interfaces', 'text', { kind: 'iface' })
        ]},
        { title: 'DNS клиентов серверных VPN (T3)', fields: [
          f('dns_hijack', 'Заворачивать DNS на роутер', 'только oc+/wdtt+ и lan_server_interfaces; br0/br1 и приватные адреса не трогаются', 'bool'),
          f('dns_hijack_target', 'Адрес резолвера', 'пусто = LAN-адрес роутера:53', 'text')
        ]},
        { title: 'CDN для списка ALWAYS (T4)', fields: [
          f('vpn_always_cdn_prefix', 'Пинить CDN-префикс', 'для адресов из vpn_always, попадающих в cdn_ranges_file (ротация edge-ов)', 'bool')
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
          f('web_token', 'Токен доступа', 'пусто = оставить как есть; «Сбросить» — снять токен', 'token'),
          f('release_check', 'Проверять новые релизы', 'показывать «!» у версии, если на GitHub есть более новый релиз', 'bool', { def: '1' }),
          f('release_check_interval', 'Период проверки релизов', 'сек; по умолчанию 12 ч', 'text', { kind: 'duration', def: '43200' })
        ]}
      ]
    },
    {
      /* Профили — подвкладки (Профиль 1…4) внутри раздела: раньше это был
       * один плоский список profile1..4, из-за чего поля профилей путались.
       * id/имена полей НЕ менялись — сохранение в susanin.conf прежнее. */
      id: 'profiles', label: 'Профили',
      subnavLabel: 'Профиль',
      subnavAfterGroup: 'Общие',  /* подвкладки рисуем сразу после этой группы */
      subnav: [1, 2, 3, 4].map(function (n) {
        return { id: 'p' + n, label: 'Профиль ' + n, profile: n };
      }),
      groups: [
        { title: 'Общие', fields: [
          f('profile_failover', 'Держать профиль на рабочем VPN', 'следить, чтобы таблица профиля указывала на первый живой egress из списка', 'bool')
        ]}
      ].concat([1, 2, 3, 4].map(function (n) {
        var p = 'profile' + n + '_';
        return { title: 'Профиль ' + n, profile: n, fields: [
          f(p + 'name', 'Имя', 'a-z, 0-9, _ ; пусто = профиль выключен', 'text', { kind: 'ident', creatable: true }),
          f(p + 'egress', 'Egress (туннель)', 'интерфейсы через запятую; порядок = приоритет — перетаскивайте чипы', 'text', { kind: 'ifacelist', creatable: true }),
          f(p + 'list', 'Файл списка', 'путь, например /opt/susanin/etc/profiles/имя.txt (по строке: домен / IP / CIDR); можно выбрать существующий файл', 'text', { kind: 'path', creatable: true }),
          f(p + 'geo_url', 'Ссылка на список (гео)', 'скачиваемый CIDR-список; кэш в var/profiles/', 'text', { creatable: true }),
          f(p + 'auto', 'Автообучение профиля', 'пополнять профиль новыми адресами из его диапазона', 'bool', { creatable: true }),
          f(p + 'table', 'Таблица маршрутизации', 'пусто = по умолчанию (201…204); занятые таблицы помечены', 'text', { kind: 'table', creatable: true }),
          f(p + 'mark', 'fwmark', 'hex; пусто = по умолчанию; занятые метки помечены', 'text', { kind: 'mark', creatable: true })
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
    ident: /[a-z0-9_]/,
    iface: /[A-Za-z0-9._-]/,
    ifacelist: /[A-Za-z0-9._, -]/,
    table: /[0-9]/,
    mark: /[0-9a-fA-Fx]/,
    path: /[A-Za-z0-9._/-]/
  };

  /* «Чиповые» поля: значение рисуется набором чипов с порядком и подсказками,
   * а не одной строкой. Порядок значим (egress_interface = приоритет фейловера,
   * egress_address сопоставляется с интерфейсами ПО ИНДЕКСУ — тоже порядок).
   * iplist/cidrlist — те же чипы: значения подсказываются из subnets[].cidr. */
  var CHIP_KINDS = { ifacelist: 1, iplist: 1, cidrlist: 1 };

  /* Поле одиночное, но с подсказками из /api/choices. */
  var CHOICE_KINDS = { iface: 'ifaces', table: 'tables', mark: 'marks', path: 'paths' };

  function isChipKind(kind) { return !!CHIP_KINDS[kind]; }
  function isChoiceKind(kind) { return !!CHOICE_KINDS[kind]; }

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

  /* Адрес без префикса: "10.8.0.2/24" -> "10.8.0.2". */
  function cidrAddress(cidr) {
    var s = String(cidr === null || cidr === undefined ? '' : cidr);
    var i = s.indexOf('/');
    return i < 0 ? s : s.slice(0, i);
  }

  /* Сеть из CIDR — считаем в JS (битовая маска, без внешних библиотек):
   * "10.8.0.2/24" -> "10.8.0.0/24", "192.168.1.1/24" -> "192.168.1.0/24".
   * /31 и /32 не «сети» в обычном смысле (точечные адреса, p2p-линки) —
   * отдаём как есть; мусор -> null. */
  function cidrNetwork(cidr) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/
      .exec(String(cidr === null || cidr === undefined ? '' : cidr));
    if (!m) return null;
    var o = [+m[1], +m[2], +m[3], +m[4]];
    var pfx = +m[5];
    if (pfx > 32) return null;
    if (o[0] > 255 || o[1] > 255 || o[2] > 255 || o[3] > 255) return null;
    if (pfx >= 31) return o.join('.') + '/' + pfx;
    var ip = ((((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]) >>> 0);
    var mask = pfx === 0 ? 0 : ((0xffffffff << (32 - pfx)) >>> 0);
    var net = (ip & mask) >>> 0;
    return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255]
      .join('.') + '/' + pfx;
  }

  /* Убрать повторы значений в наборе подсказок (одно значение — один раз). */
  function dedupeItems(items) {
    var seen = {}, out = [];
    items.forEach(function (it) {
      if (!it || !it.value) return;
      var k = String(it.value);
      if (seen[k]) return;
      seen[k] = 1;
      out.push(it);
    });
    return out;
  }

  /* Имя сетевого интерфейса: буквы/цифры/._- (nwg0, br-lan, ppp1.1). */
  function isIfaceName(s) { return /^[A-Za-z0-9._-]{1,31}$/.test(s); }

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
      case 'iface': return isIfaceName(value);
      /* Список интерфейсов: через запятую, дубликаты допустимы (порядок =
       * приоритет фейловера, поэтому НЕ сортируем и НЕ схлопываем). */
      case 'ifacelist': return value.split(',').every(function (s) { return isIfaceName(s.trim()); });
      case 'table': return /^[0-9]+$/.test(value) && +value >= 1 && +value <= 255;
      case 'mark': return /^0x[0-9a-fA-F]{1,8}$/.test(value);
      case 'path': return value.charAt(0) === '/' && value.indexOf('..') < 0 &&
        /^[A-Za-z0-9._/-]+$/.test(value);
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
      /* Подсказка «нет в списке известных» обновляется на каждый ввод:
       * предупреждаем, но не блокируем сохранение. */
      setUnknownWarn(fld._warn, fld, inp.value);
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

  /* --- подсказки «известных системе» значений (GET /api/choices) ---
   *
   * Запрос делает app.js один раз при открытии панели; здесь только чтение
   * кэша. Нет данных (старый агент, ошибка, 401) — window.susaninChoices
   * остаётся null, подсказок нет, поля работают как раньше (ручной ввод). */

  function choices() {
    var d = window.susaninChoices;
    return (d && typeof d === 'object') ? d : null;
  }

  /* Известно ли значение системе. Используется ТОЛЬКО для предупреждения:
   * сохранение не блокируется никогда. */
  function isKnownValue(kind, value) {
    var c = choices();
    var v = String(value || '').trim();
    var i;
    if (!c || !v) return true;                 /* нечем сверять — не мешаем */
    if (kind === 'iface' || kind === 'ifacelist') {
      /* Псевдо-кандидат резервного пути через Xray (0.4.0.RC1): не интерфейс
       * системы, поэтому в choices его нет — считаем известным значением. */
      if (v === 'tproxy' || v === 'xray') return true;
      var ifs = c.ifaces || [];
      for (i = 0; i < ifs.length; i++)
        if (ifs[i] && ifs[i].name === v) return true;
      return false;
    }
    if (kind === 'table') {
      var t = c.tables || [];
      for (i = 0; i < t.length; i++)
        if (String(t[i].id) === v) return true;
      return false;
    }
    if (kind === 'mark') {
      var m = c.marks || [];
      for (i = 0; i < m.length; i++)
        if (String(m[i].value).toLowerCase() === v.toLowerCase()) return true;
      var u = c.used_marks || [];
      for (i = 0; i < u.length; i++)
        if (String(u[i]).toLowerCase() === v.toLowerCase()) return true;
      return false;
    }
    if (kind === 'path') {
      var l = c.lists || [];
      for (i = 0; i < l.length; i++)
        if (l[i] && l[i].path === v) return true;
      return false;
    }
    if (kind === 'iplist' || kind === 'cidrlist') {
      /* Подсети с интерфейсов: для iplist сверяем адрес без префикса, для
       * cidrlist — сеть (или сам cidr, если префикс нестандартный). */
      var subs = c.subnets || [];
      for (i = 0; i < subs.length; i++) {
        if (!subs[i] || !subs[i].cidr) continue;
        if (kind === 'iplist') {
          if (cidrAddress(subs[i].cidr) === v) return true;
        } else if (cidrNetwork(subs[i].cidr) === v || String(subs[i].cidr) === v) {
          return true;
        }
      }
      return false;
    }
    return true;
  }

  /* Группы подсказок: набор для iface/ifacelist отличается от набора для path
   * — панель показывает только уместный список. */
  function ifaceGroups() {
    var c = choices();
    if (!c) return [];
    var tun = [], br = [], phys = [];
    (c.ifaces || []).forEach(function (it) {
      if (!it || !it.name) return;
      var opt = { value: it.name, note: it.up ? 'up' : 'down' };
      if (it.kind === 'tunnel') tun.push(opt);
      else if (it.kind === 'bridge') br.push(opt);
      else phys.push(opt);
    });
    var groups = [];
    if (tun.length) groups.push({ label: 'Туннели', items: tun });
    if (br.length) groups.push({ label: 'Мосты', items: br });
    if (phys.length) groups.push({ label: 'Физические', items: phys });
    /* Подсети здесь НЕ предлагаем: имя интерфейса и CIDR — разные вещи.
     * Подсказки из subnets[] живут в iplist/cidrlist (см. subnetChoiceItems). */
    return groups;
  }

  /* Подсказки из подсетей с интерфейсов (subnets[] = {cidr, dev}):
   *   iplist   -> адрес без префикса: 10.8.0.2/24 -> 10.8.0.2 (это адрес
   *               тоннеля, ровно то, что нужно egress_address/health_probe);
   *   cidrlist -> сеть: 192.168.1.1/24 -> 192.168.1.0/24 (/31, /32 как есть).
   * Пояснение — имя интерфейса. Повторы значений убираем. */
  function subnetChoiceItems(kind) {
    var c = choices();
    if (!c) return [];
    var out = [];
    (c.subnets || []).forEach(function (s) {
      if (!s || !s.cidr) return;
      var v;
      if (kind === 'cidrlist') {
        v = cidrNetwork(s.cidr);
      } else {
        v = cidrAddress(s.cidr);
        if (!isValidIPv4(v)) v = null;
      }
      if (!v) return;
      out.push({ value: v, note: s.dev || '' });
    });
    return dedupeItems(out);
  }

  function choiceGroupsFor(kind) {
    var c = choices();
    var groups = [];
    if (!c) return groups;
    if (kind === 'iface' || kind === 'ifacelist') return ifaceGroups();
    if (kind === 'iplist' || kind === 'cidrlist') {
      var items = subnetChoiceItems(kind);
      if (items.length) {
        groups.push({
          label: kind === 'cidrlist' ? 'Подсети интерфейсов' : 'Адреса интерфейсов',
          items: items
        });
      }
      return groups;
    }
    if (kind === 'table') {
      groups.push({ label: 'Таблицы маршрутизации', items: (c.tables || []).map(function (t) {
        return { value: String(t.id), note: t.used ? 'занята' : 'свободна' };
      }) });
      return groups;
    }
    if (kind === 'mark') {
      if ((c.marks || []).length) {
        groups.push({ label: 'Метки профилей', items: (c.marks || []).map(function (m) {
          return { value: m.value, note: m.used ? 'занята' : 'свободна' };
        }) });
      }
      if ((c.used_marks || []).length) {
        groups.push({ label: 'Уже заданы в конфиге', items: (c.used_marks || []).map(function (v) {
          return { value: v, note: 'занята' };
        }) });
      }
      return groups;
    }
    if (kind === 'path') {
      if ((c.lists || []).length) {
        groups.push({ label: 'Файлы списков', items: (c.lists || []).map(function (l) {
          return { value: l.path, note: l.name };
        }) });
      }
      if (c.list_dir) groups.push({ label: 'Каталог', items: [{ value: c.list_dir, note: 'каталог' }] });
      return groups;
    }
    return groups;
  }

  /* <select> с optgroup'ами. Значение — value, подпись — value + пояснение
   * (up/down, занята/свободна, имя файла). */
  function buildChoiceSelect(groups, opts) {
    opts = opts || {};
    var sel = document.createElement('select');
    sel.className = 'choice-select';
    var empty = document.createElement('option');
    empty.value = '';
    empty.textContent = opts.placeholder || '— выбрать известное —';
    sel.appendChild(empty);
    groups.forEach(function (g) {
      var og = document.createElement('optgroup');
      og.label = g.label;
      g.items.forEach(function (it) {
        var o = document.createElement('option');
        o.value = it.value;
        o.textContent = it.note ? it.value + '  (' + it.note + ')' : it.value;
        o.title = o.textContent;
        og.appendChild(o);
      });
      sel.appendChild(og);
    });
    return sel;
  }

  /* Предупреждение «нет в списке известных» — только текст. */
  function unknownWarn() {
    var w = document.createElement('span');
    w.className = 'warn-note';
    w.hidden = true;
    return w;
  }

  function setUnknownWarn(el, fld, value) {
    if (!el) return;
    var v = String(value || '').trim();
    if (!v || isKnownValue(fld.kind, v)) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.textContent = '«' + v + '» нет в списке известных — сохранится как есть';
  }

  /* Предупреждение для чипового списка: перечисляем неизвестные значения
   * (одним setUnknownWarn их не показать — он рассчитан на одно значение). */
  function setChipWarn(el, unknown) {
    if (!el) return;
    if (!unknown || !unknown.length) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    var shown = unknown.slice(0, 3).join(', ');
    if (unknown.length > 3)
      shown += ' …(ещё ' + (unknown.length - 3) + ')';
    el.hidden = false;
    el.textContent = 'нет в списке известных: ' + shown + ' — сохранится как есть';
  }

  /* --- чипы (ifacelist/iplist/cidrlist): порядок значим, есть drag&drop и стрелки --- */

  /* Разбор строки в список значений: порядок и дубликаты сохраняем — для
   * egress_interface порядок = приоритет фейловера. */
  function parseList(v) {
    if (!v) return [];
    return v.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return !!s; });
  }

  function joinList(arr) { return arr.join(', '); }

  /* Чиповый редактор списка. container.value — сохраняемая строка «через
   * запятую» (saveTab читает узел по [data-key]). */
  function chipList(fld, val, container) {
    var values = parseList(val);
    var warn = unknownWarn();
    var chips = document.createElement('div');
    chips.className = 'chips';
    var groups = choiceGroupsFor(fld.kind);

    function move(from, to) {
      if (from < 0 || to < 0 || to >= values.length || from === to) return;
      var v = values.splice(from, 1)[0];
      values.splice(to, 0, v);
      sync();
    }

    function makeChip(v, idx) {
      var chip = document.createElement('span');
      chip.className = 'chip' + (isKnownValue(fld.kind, v) ? '' : ' unknown');
      chip.draggable = true;
      chip.title = v;

      var handle = document.createElement('span');
      handle.className = 'chip-handle';
      handle.textContent = '⋮⋮';
      chip.appendChild(handle);

      var txt = document.createElement('span');
      txt.className = 'chip-val';
      txt.textContent = v;
      chip.appendChild(txt);

      var left = document.createElement('button');
      left.type = 'button';
      left.className = 'btn-icon chip-move';
      left.textContent = '←';
      left.title = 'Выше в списке (приоритетнее)';
      left.onclick = function () { move(idx, idx - 1); };
      chip.appendChild(left);

      var right = document.createElement('button');
      right.type = 'button';
      right.className = 'btn-icon chip-move';
      right.textContent = '→';
      right.title = 'Ниже в списке';
      right.onclick = function () { move(idx, idx + 1); };
      chip.appendChild(right);

      var del = document.createElement('button');
      del.type = 'button';
      del.className = 'btn-icon chip-del';
      del.textContent = '✕';
      del.title = 'Убрать из списка';
      del.onclick = function () { values.splice(idx, 1); sync(); };
      chip.appendChild(del);

      chip.addEventListener('dragstart', function (e) {
        e.dataTransfer.setData('text/plain', String(idx));
        e.dataTransfer.effectAllowed = 'move';
        chip.classList.add('dragging');
      });
      chip.addEventListener('dragend', function () { chip.classList.remove('dragging'); });
      chip.addEventListener('dragover', function (e) {
        e.preventDefault();
        chip.classList.add('drag-over');
      });
      chip.addEventListener('dragleave', function () { chip.classList.remove('drag-over'); });
      chip.addEventListener('drop', function (e) {
        e.preventDefault();
        chip.classList.remove('drag-over');
        var from = parseInt(e.dataTransfer.getData('text/plain'), 10);
        if (isNaN(from) || from === idx) return;
        move(from, from < idx ? idx - 1 : idx);
      });
      return chip;
    }

    function sync() {
      container.value = joinList(values);
      chips.innerHTML = '';
      if (!values.length) {
        var empty = document.createElement('span');
        empty.className = 'chips-empty';
        empty.textContent = 'пусто';
        chips.appendChild(empty);
      }
      values.forEach(function (v, idx) { chips.appendChild(makeChip(v, idx)); });
      var unknown = values.filter(function (v) { return !isKnownValue(fld.kind, v); });
      setChipWarn(warn, unknown);
    }

    container.appendChild(chips);

    var add = document.createElement('div');
    add.className = 'chips-add';
    var sel = buildChoiceSelect(groups, { placeholder: '＋ выбрать известный…' });
    sel.disabled = !groups.length;

    if (!groups.length) sel.title = 'агент не отдал список известных значений';
    add.appendChild(sel);

    var inp = document.createElement('input');
    inp.type = 'text';
    inp.className = 'chip-input';
    inp.placeholder = 'или введите вручную…';
    inp.title = 'Своё значение сохранится, даже если агент его не знает';
    add.appendChild(inp);

    function addValue(v) {
      v = String(v || '').trim();
      if (!v) return;
      if (!isValidFormat(fld, v)) {
        toast('«' + v + '» не подходит для поля «' + fld.label + '»', false);
        return;
      }
      values.push(v);
      inp.value = '';
      sel.value = '';
      sync();
    }

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-sm btn-outline';
    btn.textContent = '＋ добавить';
    btn.title = 'Добавить значение в конец (менее приоритетно)';
    btn.onclick = function () { addValue(sel.value || inp.value); };
    add.appendChild(btn);

    inp.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); addValue(inp.value); }
    });
    sel.addEventListener('change', function () {
      if (sel.value) addValue(sel.value);
    });

    container.appendChild(add);
    container.appendChild(warn);
    sync();
    return container;
  }

  /* Одиночное поле + выпадающий список известных значений. Значение в input —
   * это и есть сохраняемое значение (ручной ввод работает как раньше). */
  function attachChoicePicker(inp, fld, warn) {
    var groups = choiceGroupsFor(fld.kind);
    if (!groups.length) return null;
    var sel = buildChoiceSelect(groups, { placeholder: '＋ известное значение…' });
    sel.onchange = function () {
      if (!sel.value) return;
      inp.value = sel.value;
      sel.value = '';
      inp.dispatchEvent(new Event('input'));
      setUnknownWarn(warn, fld, inp.value);
      inp.focus();
    };
    return sel;
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
      ro.textContent = tokenSet ? 'токен задан (значение скрыто)'
        : 'токен не задан — панель работает только на чтение (изменения запрещены). Задайте токен: susanin-agent config set web_token <секрет>';
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
      cb.checked = present ? val === '1' : fld.def === '1';
      cb.dataset.key = fld.key;
      /* bool можно безопасно создать: 0/1 всегда валидны. Раньше ключ,
       * которого ещё нет в старом susanin.conf (например release_check),
       * был заблокирован и не реагировал на переключатель. */
      if (!present && !fld.creatable) cb.disabled = true;
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
        /* Ключа нет — оставляем выбор доступным: при сохранении он будет создан. */
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
    } else if (isChipKind(fld.kind)) {
      /* ifacelist: набор чипов с порядком (drag&drop и ← / →), кнопка «＋» с
       * известными интерфейсами и ручной ввод. container.value — строка
       * «через запятую», её и читает saveTab (как у обычного input). */
      var box = document.createElement('div');
      box.className = 'chips-box';
      box.dataset.key = fld.key;
      box.value = val;
      chipList(fld, val, box);
      wrap.appendChild(box);
      if (!present) wrap.appendChild(missingTag());
    } else {
      var inp = document.createElement('input');
      inp.type = fld.type === 'password' ? 'password' : (fld.type === 'number' ? 'number' : 'text');
      inp.dataset.key = fld.key;
      if (val) inp.value = val;
      else if (!present && fld.def) inp.value = fld.def;
      else inp.placeholder = present ? '(пусто)' : 'нет в файле — впишите значение, ключ будет создан';

      if (isChoiceKind(fld.kind)) {
        /* Одиночное поле с подсказками (iface/table/mark/path): значение
         * вводится как раньше, рядом — список известных значений. */
        var row = document.createElement('div');
        row.className = 'choice-row';
        row.appendChild(inp);
        var warn1 = unknownWarn();
        fld._warn = warn1;
        var picker = attachChoicePicker(inp, fld, warn1);
        if (picker) row.appendChild(picker);
        wrap.appendChild(row);
        wrap.appendChild(warn1);
        setUnknownWarn(warn1, fld, val);
      } else {
        wrap.appendChild(inp);
      }
      /* Поле без ключа в файле оставляем доступным: сервер создаст ключ, если
       * значение не пустое (пустые строки в конфиг не дописываем). */
      if (fld.kind || fld.noZero) attachValidation(inp, fld);
      if (!present) wrap.appendChild(missingTag());
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
       * в файле (иначе пустые блоки profileN_* не создаём). Имя ищем по
       * префиксу группы, а не по позиции поля: состав полей может меняться. */
      var nameKey = null;
      g.fields.forEach(function (fld) {
        if (/^profile[1-9][0-9]*_name$/.test(fld.key)) nameKey = fld.key;
      });
      if (nameKey) {
        var nl = bodyEl.querySelector('[data-key="' + nameKey + '"]');
        var nv = nl ? String(nl.value || '').trim() : '';
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
        if (el.disabled) return;
        if (el.classList && el.classList.contains('invalid')) { invalidField = fld; return; }
        var v = el.type === 'checkbox' ? (el.checked ? '1' : '0')
                                       : String(el.value == null ? '' : el.value);
        /* Чиповый список: строка собирается из чипов, но формат всё равно
         * проверяем — сервер отвергнет мусор, лучше сказать сразу. */
        if (isChipKind(fld.kind) && v && !isValidFormat(fld, v)) { invalidField = fld; return; }
        /* Ключа нет в файле — создаём только с непустым значением. */
        if (fileValue(fld.key) === undefined && v === '') return;
        push(fld.key, v);
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
    }).then(function (r) {
      if (!r.ok) {
        /* 403 = панель в режиме «только чтение» (web_token не задан). */
        if (r.status === 403) {
          throw new Error('панель только для чтения: задайте токен — ' +
                          'susanin-agent config set web_token <секрет>, затем susanin restart');
        }
        if (r.status === 401) throw new Error('нужен токен (обновите страницу с ?token=…)');
        return r.text().then(function (t) {
          var msg = (t || '').trim();
          try { var j = JSON.parse(msg); if (j && j.error) msg = j.error; } catch (e) {}
          throw new Error(msg || ('HTTP ' + r.status));
        });
      }
      return r.json();
    }).then(function (r) {
      if (r && r.ok) {
        /* web_token — write-only: после смены запоминаем/снимаем локально,
         * иначе следующий же запрос уйдёт со старым токеном. */
        try {
          if (newToken) localStorage.setItem('susanin_token', newToken);
          else if (clearToken) localStorage.removeItem('susanin_token');
        } catch (e) {}
        if (r.skipped && r.skipped.length) {
          /* Часть ключей сервер не принял — не показываем «Сохранено» молча. */
          toast('Сохранено, но не приняты ключи: ' + r.skipped.join(', '), false);
        } else {
          toast('Сохранено, конфиг перечитан агентом (SIGHUP)', true);
        }
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

  /* --- подвкладки внутри раздела (сейчас только «Профили») -------------- */

  var activeSubId = {};   /* id раздела -> id активной подвкладки */

  function isSubGroup(g) { return g && g.profile; }

  /* Профиль «не задан»: нет имени и ни одного ключа profileN_* в файле. */
  function profileUnset(n) {
    var nameKey = 'profile' + n + '_name';
    var nv = fileValue(nameKey);
    if (nv !== undefined && String(nv).trim() !== '') return false;
    var any = false;
    TABS.forEach(function (t) {
      t.groups.forEach(function (g) {
        if (g.profile !== n) return;
        g.fields.forEach(function (fld) { if (fileValue(fld.key) !== undefined) any = true; });
      });
    });
    return !any;
  }

  function ensureSubId(tab) {
    if (!tab.subnav || !tab.subnav.length) return null;
    var known = tab.subnav.some(function (s) { return s.id === activeSubId[tab.id]; });
    if (!known) activeSubId[tab.id] = tab.subnav[0].id;
    return activeSubId[tab.id];
  }

  function renderSubNav(tab) {
    var activeId = ensureSubId(tab);
    var row = document.createElement('div');
    row.className = 'cfg-subnav';
    row.setAttribute('role', 'tablist');
    tab.subnav.forEach(function (s) {
      var unset = !!(s.profile && profileUnset(s.profile));
      var b = document.createElement('button');
      b.type = 'button';
      /* Кликабельная закладка: активная заметно выделена (CSS .cfg-subtab.active).
       * Пометку «не задан» делаем приглушённым текстом внутри кнопки, а не
       * частью подписи — чтобы пустой профиль не выглядел «мёртвой» кнопкой. */
      b.className = 'cfg-subtab' + (s.id === activeId ? ' active' : '')
                                  + (unset ? ' unset' : '');
      b.setAttribute('data-subtab', s.id);
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', s.id === activeId ? 'true' : 'false');
      b.title = unset
        ? 'Профиль ' + s.profile + ' не задан — нажмите, чтобы настроить'
        : 'Настроить ' + s.label;
      b.textContent = s.label;
      if (unset) {
        var note = document.createElement('span');
        note.className = 'cfg-subtab-note';
        note.textContent = 'не задан';
        b.appendChild(note);
      }
      b.onclick = function () {
        if (activeSubId[tab.id] === s.id) return;
        activeSubId[tab.id] = s.id;
        renderPane(tab);   /* перерисовываем блок: только поля этого профиля */
      };
      row.appendChild(b);
    });
    return row;
  }

  function renderGroup(g) {
    var group = document.createElement('div');
    group.className = 'cfg-group';
    if (g.title) {
      var gt = document.createElement('div');
      gt.className = 'cfg-group-title';
      gt.textContent = g.title;
      group.appendChild(gt);
    }
    g.fields.forEach(function (fld) { group.appendChild(fieldRow(fld)); });
    return group;
  }

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

    if (tab.subnav && tab.subnav.length) {
      var activeId = ensureSubId(tab);
      tab.groups.forEach(function (g) {
        if (isSubGroup(g)) return;
        body.appendChild(renderGroup(g));
        if (tab.subnavAfterGroup && g.title === tab.subnavAfterGroup)
          body.appendChild(renderSubNav(tab));
      });
      var shown = tab.groups.filter(function (g) {
        return isSubGroup(g) && String(g.profile) === activeId.replace(/^p/, '');
      });
      /* Пустой профиль: одна понятная подсказка вместо «мёртвой» формы.
       * Поля НЕ блокируем — профиль можно завести с нуля. */
      var sub = tab.subnav.filter(function (s) { return s.id === activeId; })[0];
      if (sub && sub.profile && profileUnset(sub.profile)) {
        var hint = document.createElement('div');
        hint.className = 'cfg-profile-hint';
        hint.textContent = 'Профиль ' + sub.profile + ' не задан — впишите имя, чтобы включить ' +
          '(остальные поля станут активными). Поля ниже можно заполнять уже сейчас.';
        body.appendChild(hint);
      }
      shown.forEach(function (g) { body.appendChild(renderGroup(g)); });
    } else {
      tab.groups.forEach(function (g) { body.appendChild(renderGroup(g)); });
    }

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

  /* /api/choices приходит асинхронно (запрос делает app.js). Если панель
   * успела отрисоваться раньше — перерисуем активную закладку, чтобы в полях
   * появились подсказки. Ответ пришёл раньше отрисовки — ничего не делаем:
   * поля сразу построятся с подсказками. */
  document.addEventListener('susanin:choices', function () {
    if (confValues) selectTab(activeTabId);
  });
})();
