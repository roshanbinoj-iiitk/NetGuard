#!/usr/bin/env bash
# Prove the lab forwards traffic: ping and curl from client to server via fw.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "smoke.sh: must run as root (try: sudo $0)" >&2; exit 1; }

www="$(mktemp -d)"; echo "hello from server" > "$www/index.html"
ip netns exec server python3 -m http.server 80 --bind 10.10.2.2 --directory "$www" >/dev/null 2>&1 &
srv=$!
trap 'kill $srv 2>/dev/null; rm -rf "$www"' EXIT
for _ in $(seq 50); do ip netns exec client curl -s -o /dev/null http://10.10.2.2/ && break; sleep 0.1; done

echo "== ping client -> server"
ip netns exec client ping -c 3 -i 0.2 10.10.2.2
echo "== traceroute-ish: TTL 1 answer comes from fw"
ip netns exec client ping -c 1 -t 1 10.10.2.2 || true
echo "== curl client -> server"
ip netns exec client curl -sS http://10.10.2.2/
