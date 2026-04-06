#!/bin/bash
set -euo pipefail

LABEL="com.macbox.vmnethelper"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
HELPER_DST="/usr/local/libexec/macbox-vmnet-helper"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0"
    exit 1
fi

launchctl bootout system "$PLIST_DST" >/dev/null 2>&1 || true
rm -f "$PLIST_DST"
rm -f "$HELPER_DST"
rm -f /var/run/vmnet-helper.sock

echo "Removed ${LABEL}"
