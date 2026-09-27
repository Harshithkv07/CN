#!/bin/sh
set -e
# Load the baseline firewall (best-effort: some kernels restrict iptables in containers).
iptables-restore /etc/hrt/baseline.rules 2>/dev/null || echo "[victim] baseline iptables not loaded (continuing)"
/usr/sbin/sshd
nginx -g "daemon off;"
