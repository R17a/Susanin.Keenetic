#!/usr/bin/env python3
"""dev-web.py — локальный сервер веб-панели с МОКОМ API (dev-инструмент).

Зачем: чтобы проверять www без роутера — вёрстку, языки, сохранение конфига.
Настоящий агент не нужен: /api/* отвечают заглушкой, всё остальное отдаётся
из www/ как есть (включая www/lang/*.JSON).

Usage:
    python3 tools/dev-web.py [--port 8080] [--host 127.0.0.1]
    затем открыть http://127.0.0.1:8080/

Только для разработки: в пакет не кладётся (packaging/dev-only.txt).
"""
import argparse
import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

WWW = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'www')

STATUS = {
    'version': '0.4.2',
    'version_latest': '0.4.2',
    'update_available': False,
    'release_url': 'https://github.com/R17a/Susanin.Keenetic/releases',
    'config': '/opt/susanin/etc/susanin.conf',
    'config_present': True,
    'egress': {'interface': 'nwg0', 'type': 'interface', 'count': 1, 'table': 201,
               'mark_test': '0x1', 'mark_ok': '0x2'},
    'lists': {'vpn_always': {'file': 'vpn_always.txt', 'count': 4},
              'vpn_never': {'file': 'vpn_never.txt', 'count': 3}},
    'profiles': [{'name': 'media', 'egress': 'nwg1', 'table': 202, 'mark': '0x2'}],
    'web': {'enable': 1, 'listen': '192.168.1.1', 'port': 8088, 'token_set': True},
    'ipsets': {'susanin_ok_net': 1234, 'susanin_never': 27,
               'susanin_direct': 0, 'susanin_ok_dom': 12},
}

CONFIG = {
    'egress_interface': 'nwg0, wdtt0',
    'egress_address': '10.8.0.2, 10.9.0.1',
    'egress_type': 'interface',
    'tproxy_port': '1080',
    'udp_relay': '1',
    'udp_relay_port': '1081',
    'socks_addr': '127.0.0.1',
    'socks_port': '1080',
    'egress_failback': '1',
    'egress_failback_debounce': '30',
    'egress_race': '0',
    'auto_direct': '1',
    'direct_pref_ttl': '600',
    'lan_interfaces': 'br0',
    'lan_subnets': '192.168.1.0/24',
    'lan_server_interfaces': 'oc1',
    'discover_exclude': '',
    'routing_table': '201',
    'mark_test': '0x1',
    'mark_ok': '0x2',
    'mark_mask': '0xff',
    'ip_rule_priority_start': '1000',
    'kernel_offload': '1',
    'kernel_egress': 'nwg0',
    'kernel_offload_max': '24',
    'mss_clamp': '1380',
    'mss_clamp_lan': '0',
    'fast_interval': '3',
    'soft_interval': '10',
    'judge_interval': '20',
    'health_interval': '30',
    'dp_check_interval': '60',
    'fast_syn_min_op': '3',
    'ok_ttl': '21600',
    'ok_refresh_below': '6',
    'ok_max_entries': '20000',
    'promo_per_min': '20',
    'ok_evict_misses': '2',
    'test_ttl': '30',
    'cooldown_ttl': '120',
    'cooldown_ok_ttl': '3600',
    'watch_ttl': '60',
    'watch_retry_below': '30',
    'health_probe': '1.1.1.1, 8.8.8.8',
    'health_miss_debounce': '3',
    'health_mode': 'icmp',
    'health_tcp_port': '443',
    'vpn_always_interval': '3600',
    'vpn_always_dns': '',
    'vpn_never_interval': '3600',
    'pin_reassert': '1',
    'learn_min_op': '5',
    'learn_min_bytes': '2048',
    'confirm_min_bytes': '4096',
    'learn_strict': '0',
    'precision': 'normal',
    'port_aware': '0',
    'learn_exclude_ports': '22,25,53',
    'cdn_ranges_url': 'https://www.cloudflare.com/ips-v4',
    'cdn_ranges_interval': '86400',
    'cdn_prefix_learn': '1',
    'cdn_prefix_ttl': '21600',
    'cdn_prefix_max': '24',
    'aggregate_confirm': '2',
    'ipv6_block': '1',
    'quic_block': '0',
    'xray_watchdog': '1',
    'xray_gogc': '50',
    'xray_gomemlimit': '64MiB',
    'dns_sniff': '1',
    'dns_sniff_ttl': '300',
    'dns_sniff_iface': '',
    'dns_hijack': '0',
    'dns_hijack_target': '',
    'vpn_always_cdn_prefix': '1',
    'media_enabled': '0',
    'media_ports': '80,443,554,1935,8080',
    'media_min_bytes': '1048576',
    'media_ratio': '8',
    'media_min_rate': '150000',
    'media_min_age': '12',
    'media_ttl': '21600',
    'media_prefix_max': '24',
    'log_level': 'info',
    'xray_loglevel': 'warning',
    'disk_mode': 'normal',
    'soft_state_interval': '6',
    'web_enable': '1',
    'web_listen': '192.168.1.1',
    'web_port': '8088',
    'release_check': '1',
    'release_check_interval': '43200',
    'profile_failover': '1',
    'profile1_name': 'media',
    'profile1_egress': 'nwg1',
    'profile1_list': '/opt/susanin/etc/profiles/media.txt',
    'profile1_geo_url': '',
    'profile1_auto': '1',
    'profile1_table': '202',
    'profile1_mark': '0x2',
}

LISTS = {
    'vpn_always': ['youtube.com', '*.googlevideo.com', '1.2.3.0/24', 'telegram.org'],
    'vpn_never': ['192.168.1.0/24', 'keenetic.com', '*.local'],
}
LISTS_RAW = {
    'vpn_always': "# домены и адреса, которые всегда через VPN\nyoutube.com\n*.googlevideo.com\n1.2.3.0/24\ntelegram.org\n",
    'vpn_never': "# всегда напрямую\n192.168.1.0/24\nkeenetic.com\n*.local\n",
}

CHOICES = {
    'ifaces': [
        {'name': 'nwg0', 'kind': 'tunnel', 'up': True},
        {'name': 'nwg1', 'kind': 'tunnel', 'up': True},
        {'name': 'wdtt0', 'kind': 'tunnel', 'up': False},
        {'name': 'br0', 'kind': 'bridge', 'up': True},
        {'name': 'eth3', 'kind': 'physical', 'up': True},
        {'name': 'wlan0', 'kind': 'physical', 'up': True},
    ],
    'subnets': [
        {'cidr': '192.168.1.1/24', 'dev': 'br0'},
        {'cidr': '10.8.0.2/24', 'dev': 'nwg0'},
        {'cidr': '10.9.0.1/24', 'dev': 'wdtt0'},
    ],
    'tables': [{'id': 201, 'used': True}, {'id': 202, 'used': True},
               {'id': 203, 'used': False}, {'id': 204, 'used': False}],
    'marks': [{'value': '0x1', 'used': True}, {'value': '0x2', 'used': True},
              {'value': '0x3', 'used': False}],
    'used_marks': ['0x1', '0x2'],
    'lists': [{'path': '/opt/susanin/etc/profiles/media.txt', 'name': 'media'}],
    'list_dir': '/opt/susanin/etc/profiles/',
    'free_mark_index': 2,
}

LOG = """susanin-agent 0.4.2 (dev-web mock)
engine started (egress=nwg0 table=201)
health nwg0: ICMP 3/3, TCP 3 — считаю живым
vpn_always: +4/-0 ip, +1/-0 net, 4 domain(s), now 9 ip + 2 net pinned
CDN: загружено 15 диапазонов из https://www.cloudflare.com/ips-v4
"""


class Handler(BaseHTTPRequestHandler):
    server_version = 'susanin-dev-web/1'

    def log_message(self, fmt, *args):
        sys.stderr.write("[dev-web] %s\n" % (fmt % args))

    # --- helpers ---
    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, code=200):
        body = text.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, code=200):
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, rel):
        rel = rel.lstrip('/') or 'index.html'
        full = os.path.realpath(os.path.join(WWW, rel))
        if not full.startswith(os.path.realpath(WWW) + os.sep) and full != os.path.realpath(WWW):
            return self.send_text('forbidden\n', 403)
        if os.path.isdir(full):
            full = os.path.join(full, 'index.html')
        if not os.path.isfile(full):
            return self.send_text('not found\n', 404)
        ctype = mimetypes.guess_type(full)[0] or 'application/octet-stream'
        with open(full, 'rb') as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    # --- HTTP ---
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        path = u.path

        if path == '/api/status':
            return self.send_json(STATUS)
        if path == '/api/config':
            return self.send_json({'file': '/opt/susanin/etc/susanin.conf',
                                   'params': CONFIG, 'token_set': True})
        if path == '/api/choices':
            return self.send_json(CHOICES)
        if path == '/api/log':
            return self.send_text(LOG)
        if path == '/api/list':
            name = (qs.get('name') or [''])[0]
            return self.send_json(LISTS.get(name, []))
        if path == '/api/list/raw':
            name = (qs.get('name') or [''])[0]
            return self.send_text(LISTS_RAW.get(name, ''))
        if path == '/__lang':
            # Помощник для проверки: /__lang?code=en запоминает выбор и уводит
            # на панель (удобно для headless-скриншотов и быстрых прогонов).
            code = (qs.get('code') or ['ru'])[0]
            if code not in ('ru', 'en', 'zh'):
                code = 'ru'
            body = ("<!doctype html><meta charset=\"utf-8\">"
                    "<script>try{localStorage.setItem('susanin_lang','%s');}"
                    "catch(e){}location.replace('/');</script>" % code)
            return self.send_html(body)
        if path.startswith('/api/'):
            return self.send_json({'ok': True})
        return self.send_static(path)

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) if length else b''
        if u.path == '/api/config':
            # Разбираем form-urlencoded, чтобы dev-сервер вёл себя как агент:
            # принятые ключи запоминаем в памяти процесса.
            from urllib.parse import parse_qsl
            skipped = []
            for k, v in parse_qsl(raw.decode('utf-8'), keep_blank_values=True):
                if k == 'web_token':
                    continue
                CONFIG[k] = v
            return self.send_json({'ok': True, 'skipped': skipped})
        if u.path == '/api/list':
            from urllib.parse import parse_qsl
            form = dict(parse_qsl(raw.decode('utf-8'), keep_blank_values=True))
            name = form.get('list', '')
            val = form.get('value', '')
            items = LISTS.setdefault(name, [])
            if form.get('op') == 'add' and val not in items:
                items.append(val)
            elif form.get('op') == 'del' and val in items:
                items.remove(val)
            return self.send_json({'ok': True})
        if u.path == '/api/list/save':
            from urllib.parse import parse_qsl
            form = dict(parse_qsl(u.query, keep_blank_values=True))
            name = form.get('name', '')
            text = raw.decode('utf-8', 'replace')
            kept = [l for l in text.splitlines() if l.strip() and not l.strip().startswith('#')]
            LISTS_RAW[name] = text
            LISTS[name] = [l.strip() for l in kept]
            return self.send_json({'ok': True, 'kept': len(kept), 'dropped': 0})
        if u.path.startswith('/api/'):
            return self.send_json({'ok': True})
        return self.send_text('not found\n', 404)


def system_proxy_ports():
    """Порты системного HTTP-прокси Windows (WinINET) — только для предупреждения.

    Если dev-сервер займёт порт, на который настроен прокси браузера/системы,
    панель по localhost откроется (localhost обычно в обход прокси), а весь
    остальной трафик пойдёт в наш мок-сервер — со стороны это выглядит как
    «пропал интернет». Поэтому такой порт лучше не занимать.
    """
    ports = set()
    if os.name != 'nt':
        return ports
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
        try:
            enabled, _ = winreg.QueryValueEx(key, 'ProxyEnable')
        except OSError:
            enabled = 0
        try:
            server, _ = winreg.QueryValueEx(key, 'ProxyServer')
        except OSError:
            server = ''
        winreg.CloseKey(key)
        if not enabled or not server:
            return ports
        for part in str(server).split(';'):
            part = part.split('=')[-1].strip()
            if ':' in part:
                tail = part.rsplit(':', 1)[1].strip('/')
                if tail.isdigit():
                    ports.add(int(tail))
    except Exception:
        pass
    return ports


def main():
    ap = argparse.ArgumentParser(description='Локальный сервер веб-панели с мок-API (dev)')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--host', default='127.0.0.1')
    args = ap.parse_args()
    if not os.path.isdir(WWW):
        sys.exit('dev-web: нет каталога %s' % WWW)
    proxied = system_proxy_ports()
    if args.port in proxied:
        sys.exit('dev-web: порт %d занят системным прокси — занимать его нельзя,\n'
                 'иначе браузерный трафик уйдёт в этот мок-сервер и «пропадёт интернет».'
                 % args.port)
    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        sys.exit('dev-web: не удалось занять %s:%d (%s) — выберите другой порт: --port 8099'
                 % (args.host, args.port, exc))
    print('dev-web: http://%s:%d/  (www=%s, API — заглушка)' % (args.host, args.port, WWW))
    print('dev-web: сервер ЛОКАЛЬНЫЙ, к роутеру не подключается и на маршрутизацию не влияет')
    if proxied:
        print('dev-web: системный прокси слушает порт(ы) %s — этот порт не занимаем'
              % ', '.join(str(p) for p in sorted(proxied)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\ndev-web: остановлено')


if __name__ == '__main__':
    main()
