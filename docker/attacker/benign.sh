#!/bin/sh
# Steady, low-rate benign traffic to the protected server, so the baseline isn't empty.
VICTIM=10.10.0.10
echo "[benign] generating baseline traffic to ${VICTIM}"
while true; do
  curl -s -o /dev/null "http://${VICTIM}/" || true
  sleep $(awk "BEGIN{srand();print 2+rand()*4}")
  # occasional legitimate SSH banner grab from an allowed host
  if [ $((RANDOM % 5)) -eq 0 ]; then
    (echo "" | nc -w 2 "${VICTIM}" 22) >/dev/null 2>&1 || true
  fi
done
