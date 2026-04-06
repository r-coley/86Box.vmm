#!/bin/bash
set -euo pipefail

LABEL="com.macbox.vmnethelper"
PLIST_SRC="launchd/${LABEL}.plist"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
HELPER_SRC="build/vmnet-helper"
HELPER_DST="/usr/local/libexec/macbox-vmnet-helper"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0"
    exit 1
fi

if [[ ! -f "$HELPER_SRC" ]]; then
    echo "Missing $HELPER_SRC. Build first with: make"
    exit 1
fi

mkdir -p /usr/local/libexec
install -m 755 "$HELPER_SRC" "$HELPER_DST"
install -m 644 "$PLIST_SRC" "$PLIST_DST"

chown root:wheel "$HELPER_DST" "$PLIST_DST"

launchctl bootout system "$PLIST_DST" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable "system/${LABEL}"
launchctl kickstart -k "system/${LABEL}"

echo "Installed and started ${LABEL}"
echo "Socket: /var/run/vmnet-helper.sock"
echo "Logs:"
plutil -p launchd/com.macbox.vmnethelper.plist | grep -E 'StandardOutPath|StandardErrorPath'
