Xray-core — дистрибутив для режима Susanin egress_type=tproxy.

Файлы:
  xray.mipsel    Xray 1.8.24, linux/mips32le, softfloat (Keenetic mipsel).
  xray.aarch64   Xray 1.8.24, linux/arm64-v8a  (Keenetic aarch64).
  LICENSE        лицензия Xray-core (MPL-2.0).

Установка (на роутере) — по архитектуре:
  cp xray.mipsel  /opt/sbin/xray && chmod +x /opt/sbin/xray   # mips/mipsel
  cp xray.aarch64 /opt/sbin/xray && chmod +x /opt/sbin/xray   # aarch64

Новые версии Xray/Go на ядре Keenetic (4.9) могут падать — используйте
проверенную 1.8.24. Источник: github.com/XTLS/Xray-core (Releases).
