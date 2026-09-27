#!/bin/sh
# Decode the ruleset, syntax-test it against the real kernel parser, then commit and print it.
set -eu
RULES="$(printf '%s' "${RULESET_B64:-}" | base64 -d 2>/dev/null || true)"
if [ -z "$RULES" ]; then
  echo "empty ruleset" >&2
  exit 3
fi
if ! printf '%s\n' "$RULES" | iptables-restore --test 2>/tmp/err; then
  cat /tmp/err >&2
  exit 1
fi
if ! printf '%s\n' "$RULES" | iptables-restore 2>/tmp/err; then
  cat /tmp/err >&2
  exit 2
fi
iptables -S
