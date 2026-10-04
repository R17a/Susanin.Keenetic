Xray-core — дистрибутив для режима Susanin egress_type=tproxy.

В dev-архив (susanin-keenetic-0.4.0-dev.tar.gz) бинарники Xray НЕ входят:
каждый весит ~29 МБ (в сжатом виде ~19 МБ на двоих), а нужны они только тем,
кто включает egress_type=tproxy. Без них архив ~2 МБ — меньше качать и меньше
писать на флеш роутера. Сами файлы лежат в репозитории, папка develop/xray/.

Файлы:
  xray.mipsel    Xray 1.8.24, linux/mips32le, softfloat (Keenetic mipsel).
  xray.aarch64   Xray 1.8.24, linux/arm64-v8a  (Keenetic aarch64).
  SHA256SUMS     контрольные суммы этих двух бинарников.
  LICENSE        лицензия Xray-core (MPL-2.0).

Проще всего — установщик скачает нужный бинарник и положит в /opt/sbin/xray:
  sh bootstrap.sh --with-xray --yes

Вручную (на роутере, по архитектуре):
  wget -O /opt/sbin/xray \
    https://raw.githubusercontent.com/R17a/Susanin.Keenetic/develop/develop/xray/xray.mipsel
  # aarch64: .../develop/xray/xray.aarch64
  chmod +x /opt/sbin/xray
  # сверить: sha256sum /opt/sbin/xray  (значение — в xray/SHA256SUMS)

Новые версии Xray/Go на ядре Keenetic (4.9) могут падать — используйте
проверенную 1.8.24. Источник: github.com/XTLS/Xray-core (Releases).
