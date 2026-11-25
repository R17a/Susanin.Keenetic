# Susanin AY — server for Ubuntu (x86-64)

**Русский** · [English](#english) · [简体中文](#简体中文)

## Русский

Готовый статический бинарник сервера туннеля и установщик под Ubuntu (x86-64).
Исходных кодов в комплекте нет — только исполняемый файл и скрипты установки.

### Платформа

Комплект собран для Ubuntu x86-64: установщик ставит пакеты через `apt`,
настраивает `systemd`-юнит и `dnsmasq`, вызывает `iptables`/`ip`/`sysctl`.
На других системах (Alpine, RHEL, OpenWrt, arm64 и т.п.) он не рассчитан —
для них нужна отдельная сборка.

### Состав

- `build/susanin-tunnel-server.x86_64` — статический бинарник (Ubuntu x86-64);
- `install-vps.sh` — установка на VPS/VDI с Ubuntu (язык вывода: русский,
  английский, упрощённый китайский; выбирается по `LANG`/`LC_ALL`, по умолчанию
  английский, переопределяется `AY_LANG=ru|en|zh`);
- `server/config/tunnel-server.conf.example` — пример конфигурации;
- `server/systemd/susanin-tunnel-server.service` — systemd-юнит;
- `server/tools/vps-setup.sh` — sysctl/NAT/MSS/rp_filter (вызывается установщиком);
- `SHA256SUMS` — контрольные суммы.

### Установка

```sh
sha256sum -c SHA256SUMS
sudo sh install-vps.sh            # английский по умолчанию
sudo AY_LANG=ru sh install-vps.sh # русский
sudo AY_LANG=zh sh install-vps.sh # 简体中文
```

Установщик идемпотентен: бинарник кладётся в `/usr/local/sbin`, ключ
`/etc/susanin/tunnel.key` и конфиг `/etc/susanin/tunnel-server.conf` при
повторном запуске не перезаписываются.

После установки:

```sh
systemctl status susanin-tunnel-server
journalctl -u susanin-tunnel-server -n 50 --no-pager
```

### Параметры для роутера

Установщик печатает ключ и адрес. В панели роутера:

- `ay_server` — публичный адрес VPS;
- `ay_port` — UDP-порт (по умолчанию 5004);
- `ay_key` — содержимое `/etc/susanin/tunnel.key`.

DNS клиентов LAN при `dns_lan=1` и `dns_lan_via=ay` идёт на `10.23.0.1:53`;
серверный `dnsmasq` поднимает этот адрес сам.

### Firewall

Откройте UDP-порт туннеля (по умолчанию 5004/udp) на внешнем интерфейсе.
Установщик настраивает NAT/MSS для трафика из `10.23.0.0/24`.

### Проверка

```sh
/usr/local/sbin/susanin-tunnel-server --help
/usr/local/sbin/susanin-tunnel-server --keygen
```

`--keygen` печатает новый ключ; его же нужно прописать в `ay_key` на роутере.

## English

A ready-to-run static tunnel server binary and installer for Ubuntu (x86-64).
No source code is included — only the executable and installation scripts.

### Platform

Built for Ubuntu x86-64: the installer uses `apt`, sets up a `systemd` unit and
`dnsmasq`, and calls `iptables`/`ip`/`sysctl`. It is not intended for other
systems (Alpine, RHEL, OpenWrt, arm64, etc.) — build separately for those.

### Contents

- `build/susanin-tunnel-server.x86_64` — static binary (Ubuntu x86-64);
- `install-vps.sh` — installation on a VPS/VDI with Ubuntu (output language:
  Russian, English, Simplified Chinese; detected from `LANG`/`LC_ALL`, English
  by default, override with `AY_LANG=ru|en|zh`);
- `server/config/tunnel-server.conf.example` — configuration example;
- `server/systemd/susanin-tunnel-server.service` — systemd unit;
- `server/tools/vps-setup.sh` — sysctl/NAT/MSS/rp_filter (called by the installer);
- `SHA256SUMS` — checksums.

### Install

```sh
sha256sum -c SHA256SUMS
sudo sh install-vps.sh            # English by default
sudo AY_LANG=ru sh install-vps.sh # Russian
sudo AY_LANG=zh sh install-vps.sh # Simplified Chinese
```

The installer is idempotent: the binary goes to `/usr/local/sbin`, while the key
`/etc/susanin/tunnel.key` and the config `/etc/susanin/tunnel-server.conf` are
never overwritten on re-run.

After installation:

```sh
systemctl status susanin-tunnel-server
journalctl -u susanin-tunnel-server -n 50 --no-pager
```

### Router parameters

The installer prints the key and the address. In the router panel:

- `ay_server` — public address of the VPS;
- `ay_port` — UDP port (5004 by default);
- `ay_key` — contents of `/etc/susanin/tunnel.key`.

With `dns_lan=1` and `dns_lan_via=ay`, LAN clients resolve through
`10.23.0.1:53`; the server-side `dnsmasq` listens on that address.

### Firewall

Open the tunnel UDP port (5004/udp by default) on the external interface.
The installer sets up NAT/MSS for traffic from `10.23.0.0/24`.

### Check

```sh
/usr/local/sbin/susanin-tunnel-server --help
/usr/local/sbin/susanin-tunnel-server --keygen
```

`--keygen` prints a new key; put the same value into `ay_key` on the router.

## 简体中文

适用于 Ubuntu (x86-64) 的隧道服务器静态二进制文件和安装脚本。
安装包中不包含源代码，只有可执行文件和安装脚本。

### 平台

为 Ubuntu x86-64 构建：安装脚本通过 `apt` 安装依赖，配置 `systemd` 服务和
`dnsmasq`，并调用 `iptables`/`ip`/`sysctl`。不支持其他系统（Alpine、RHEL、
OpenWrt、arm64 等）——如需使用请单独构建。

### 内容

- `build/susanin-tunnel-server.x86_64` — 静态二进制文件（Ubuntu x86-64）；
- `install-vps.sh` — 在 Ubuntu 的 VPS/VDI 上安装（输出语言：俄语、英语、
  简体中文；根据 `LANG`/`LC_ALL` 自动选择，默认英语，可用 `AY_LANG=ru|en|zh`
  指定）；
- `server/config/tunnel-server.conf.example` — 配置示例；
- `server/systemd/susanin-tunnel-server.service` — systemd 服务单元；
- `server/tools/vps-setup.sh` — sysctl/NAT/MSS/rp_filter（由安装脚本调用）；
- `SHA256SUMS` — 校验和。

### 安装

```sh
sha256sum -c SHA256SUMS
sudo sh install-vps.sh            # 默认英语
sudo AY_LANG=ru sh install-vps.sh # 俄语
sudo AY_LANG=zh sh install-vps.sh # 简体中文
```

安装脚本是幂等的：二进制文件安装到 `/usr/local/sbin`，重复运行时不会覆盖
密钥 `/etc/susanin/tunnel.key` 和配置 `/etc/susanin/tunnel-server.conf`。

安装完成后：

```sh
systemctl status susanin-tunnel-server
journalctl -u susanin-tunnel-server -n 50 --no-pager
```

### 路由器参数

安装脚本会输出密钥和地址。在路由器面板中填写：

- `ay_server` — VPS 的公网地址；
- `ay_port` — UDP 端口（默认 5004）；
- `ay_key` — `/etc/susanin/tunnel.key` 的内容。

当 `dns_lan=1` 且 `dns_lan_via=ay` 时，局域网客户端的 DNS 请求走
`10.23.0.1:53`，由服务器端的 `dnsmasq` 响应。

### 防火墙

请在外网接口放行隧道的 UDP 端口（默认 5004/udp）。
安装脚本会为 `10.23.0.0/24` 的流量配置 NAT/MSS。

### 检查

```sh
/usr/local/sbin/susanin-tunnel-server --help
/usr/local/sbin/susanin-tunnel-server --keygen
```

`--keygen` 会输出新密钥；请将同样的值填入路由器的 `ay_key`。
