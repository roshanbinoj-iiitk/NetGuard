#!/usr/bin/env bash
# Reset the lab's *dynamic* state without rebuilding the topology:
# stop processes running in the namespaces, clear firewall rules and
# conntrack in fw, and empty every ARP (neighbour) cache.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "flush.sh: must run as root (try: sudo $0)" >&2; exit 1; }

for ns in client fw server; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip -n "$ns" neigh flush all 2>/dev/null || true
done
if command -v nft >/dev/null; then ip netns exec fw nft flush ruleset; fi
if command -v iptables >/dev/null; then ip netns exec fw iptables -F 2>/dev/null || true; fi
if command -v conntrack >/dev/null; then ip netns exec fw conntrack -F 2>/dev/null || true; fi
echo "lab flushed"
