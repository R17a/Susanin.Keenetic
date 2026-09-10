#!/bin/sh
# manual.install.sh — install Susanin.Keenetic on the router (run over SSH).
#
# Extract the per-arch deployment archive and run:
#   sh manual.install.sh
# Idempotent: existing susanin.conf is kept (use --force to overwrite).
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

DEST=/opt/susanin
BIN=$DEST/bin
ETC=$DEST/etc
VAR=$DEST/var
TOOLS=$DEST/tools
INITD=/opt/etc/init.d

need() {
    if [ ! -f "$DIR/$1" ]; then
        echo "error: file '$1' is missing next to this script" >&2
        echo "extract the full deployment archive first, then run: sh manual.install.sh" >&2
        exit 1
    fi
}

if [ -f "$DIR/susanin-agent" ]; then
    BINFILE=susanin-agent
elif [ -f "$DIR/susanin-agent.mipsel" ]; then
    BINFILE=susanin-agent.mipsel
elif [ -f "$DIR/susanin-agent.aarch64" ]; then
    BINFILE=susanin-agent.aarch64
elif [ -f "$DIR/susanin-agent.armv7" ]; then
    BINFILE=susanin-agent.armv7
else
    BINFILE=$(ls "$DIR"/susanin-agent.* 2>/dev/null | head -1)
fi
[ -n "${BINFILE:-}" ] || { echo "error: susanin-agent binary not found in $DIR" >&2; exit 1; }

need datapath.sh
need susanin.sh
need config.example.conf
need S94susanin

echo "[susanin] installing to $DEST (binary $(basename "$BINFILE")) ..."
mkdir -p "$BIN" "$ETC" "$VAR" "$TOOLS" "$INITD"

cp "$DIR/$BINFILE"             "$BIN/susanin-agent"
cp "$DIR/datapath.sh"          "$TOOLS/datapath.sh"
cp "$DIR/susanin.sh"           "$TOOLS/susanin.sh"
for f in update.sh uninstall.sh install.sh; do
    [ -f "$DIR/$f" ] && cp "$DIR/$f" "$TOOLS/$f"
done
if [ ! -f "$ETC/susanin.conf" ] || [ "$FORCE" = 1 ]; then
    cp "$DIR/config.example.conf" "$ETC/susanin.conf"
fi
[ -f "$DIR/S94susanin" ] && cp "$DIR/S94susanin" "$INITD/S94susanin"
[ -f "$DIR/vpn_always.example.txt" ] && cp "$DIR/vpn_always.example.txt" "$ETC/vpn_always.example.txt"

chmod +x "$BIN/susanin-agent" "$TOOLS/"*.sh "$INITD/S94susanin" 2>/dev/null || true

echo "[susanin] installed:"
echo "  binary   $BIN/susanin-agent"
echo "  datapath $TOOLS/datapath.sh"
echo "  control  $TOOLS/susanin.sh   (start|stop|restart|status|log|install|update|uninstall|down|add|del)"
echo "  config   $ETC/susanin.conf"
echo "  example  $ETC/vpn_always.example.txt   (домены \"всегда через VPN\")"
echo "  init     $INITD/S94susanin"
echo
echo "  quick: sh $TOOLS/susanin.sh start"
echo "         sh $TOOLS/susanin.sh status"
