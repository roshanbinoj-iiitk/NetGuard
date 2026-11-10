#!/usr/bin/env bash
# Remove the lab completely. Safe to run when the lab is absent or half-built.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "teardown.sh: must run as root (try: sudo $0)" >&2; exit 1; }

for ns in client fw server; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        # A namespace lives on while any process is inside it, so stop
        # servers/captures first, then drop the name.
        ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        ip netns del "$ns"
    fi
done
# If an earlier setup died before moving the veths, they are still here.
for dev in veth-c veth-s veth-fc veth-fs; do
    ip link del "$dev" 2>/dev/null || true
done
echo "lab down"
