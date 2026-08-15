#!/bin/bash
echo "Simulating benign HTTP traffic..."
docker run --rm --network hrt-agent_hrt-net alpine/curl curl -s http://victim-server > /dev/null

echo "Simulating port scan..."
docker run --rm --network hrt-agent_hrt-net instrumentisto/nmap -sS -p 1-1024 victim-server
echo "Traffic simulation complete."
