#!/usr/bin/env bash
# Capture the three week-1 sample pcaps on fw's client-facing interface
# (veth-fc). Capturing on a real Ethernet-like device gives linktype 1
# (EN10MB); `-i any` would give Linux cooked captures (linktype 113).
#
# Usage: sudo lab/capture_samples.sh [outdir]      (default: lab/samples)
# Needs a running lab (lab/setup.sh). Set TCPDUMP=/path/to/tcpdump to override.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "capture_samples.sh: must run as root (try: sudo $0)" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(realpath -m "${1:-$HERE/samples}")"
TCPDUMP="${TCPDUMP:-tcpdump}"
mkdir -p "$OUT"

# Targets on the server: a tiny HTTP site and a UDP echo service on 9999.
www="$(mktemp -d)"; echo "hello from server" > "$www/index.html"
ip netns exec server python3 -m http.server 80 --bind 10.10.2.2 --directory "$www" >/dev/null 2>&1 &
http_pid=$!
ip netns exec server python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.10.2.2", 9999))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data.upper(), peer)
' &
udp_pid=$!
trap 'kill $http_pid $udp_pid 2>/dev/null; rm -rf "$www"' EXIT
for _ in $(seq 50); do ip netns exec client curl -s -o /dev/null http://10.10.2.2/ && break; sleep 0.1; done

# capture NAME BPF-FILTER COMMAND... : record only the traffic COMMAND makes.
capture() {
    local name=$1 filter=$2; shift 2
    ip netns exec fw "$TCPDUMP" -i veth-fc -nn -U -Z root -w "$OUT/$name.pcap" "$filter" 2>/dev/null &
    local cap=$!
    sleep 1                      # let tcpdump attach before traffic starts
    ip netns exec client "$@" >/dev/null
    sleep 1                      # let the last replies arrive
    kill -INT "$cap"; wait "$cap" || true
    echo "wrote $OUT/$name.pcap"
}

capture icmp     "icmp"          ping -c 4 -i 0.2 10.10.2.2
capture tcp_http "tcp port 80"   curl -s http://10.10.2.2/
capture udp      "udp port 9999" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
for msg in (b"hello", b"netguard week 1", b"x" * 100):
    s.sendto(msg, ("10.10.2.2", 9999))
    s.recvfrom(2048)
'
