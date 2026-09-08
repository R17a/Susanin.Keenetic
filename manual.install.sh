#!/bin/sh
# manual.install.sh — install Susanin.Keenetic on the router (run over SSH).
#
# Put this script next to the other files of the deployment archive:
#   susanin-agent.mipsel, datapath.sh, config.example.conf, S94susanin
# then run on the router:
#   sh manual.install.sh
#
# It installs files to /opt/susanin/... and prints the next steps.
# Safe to run multiple times (idempotent).

set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

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

need susanin-agent.mipsel
need datapath.sh
need susanin.sh
need config.example.conf
need S94susanin

echo "[susanin] installing to $DEST ..."
mkdir -p "$BIN" "$ETC" "$VAR" "$TOOLS" "$INITD"

cp "$DIR/susanin-agent.mipsel" "$BIN/susanin-agent"
cp "$DIR/datapath.sh"          "$TOOLS/datapath.sh"
cp "$DIR/susanin.sh"           "$TOOLS/susanin.sh"
cp "$DIR/config.example.conf"  "$ETC/susanin.conf"
cp "$DIR/S94susanin"           "$INITD/S94susanin"
if [ -f "$DIR/vpn_always.example.txt" ]; then
    cp "$DIR/vpn_always.example.txt" "$ETC/vpn_always.example.txt"
fi

chmod +x "$BIN/susanin-agent" "$TOOLS/datapath.sh" "$TOOLS/susanin.sh" "$INITD/S94susanin"

echo "[susanin] installed:"
echo "  binary   $BIN/susanin-agent"
echo "  datapath $TOOLS/datapath.sh"
echo "  control  $TOOLS/susanin.sh   (start|stop|restart|status|log|install|down|add|del)"
echo "  config   $ETC/susanin.conf"
echo "  example  $ETC/vpn_always.example.txt   (домены \"всегда через VPN\")"
echo "  init     $INITD/S94susanin"
echo
echo "  quick: sh $TOOLS/susanin.sh start"
echo "         sh $TOOLS/susanin.sh status"
