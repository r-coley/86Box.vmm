#!/bin/bash
set -euo pipefail

LABEL="com.macbox.vmnethelper"

echo "launchctl print:"
launchctl print "system/${LABEL}" || true
echo
echo "socket:"
ls -l /var/run/vmnet-helper.sock || true
echo
echo "process:"
ps aux | grep macbox-vmnet-helper | grep -v grep || true
echo
echo "logs:"
ls -l /tmp/vmnet-helper*.log || true
