#!/usr/bin/env bash
# Build the three-namespace lab:
#
#   [client] veth-c 10.10.1.2 ── veth-fc 10.10.1.1 [fw] 10.10.2.1 veth-fs ── veth-s 10.10.2.2 [server]
#
# Idempotent: it always tears down any previous lab first, so every run
# starts from the same clean slate. Run as root: sudo lab/setup.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "setup.sh: must run as root (try: sudo $0)" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$HERE/teardown.sh" >/dev/null

for ns in client fw server; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    # Week 1 parses IPv4 only; turning IPv6 off keeps captures free of
    # router-solicitation / neighbour-discovery noise.
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done

# Two veth pairs (virtual cables). Each end is moved into its namespace.
ip link add veth-c type veth peer name veth-fc
ip link add veth-s type veth peer name veth-fs
ip link set veth-c  netns client
ip link set veth-fc netns fw
ip link set veth-s  netns server
ip link set veth-fs netns fw

ip -n client addr add 10.10.1.2/24 dev veth-c;  ip -n client link set veth-c  up
ip -n fw     addr add 10.10.1.1/24 dev veth-fc; ip -n fw     link set veth-fc up
ip -n fw     addr add 10.10.2.1/24 dev veth-fs; ip -n fw     link set veth-fs up
ip -n server addr add 10.10.2.2/24 dev veth-s;  ip -n server link set veth-s  up

ip -n client route add default via 10.10.1.1
ip -n server route add default via 10.10.2.1
ip netns exec fw sysctl -qw net.ipv4.ip_forward=1

echo "lab up: client 10.10.1.2 <-> fw (10.10.1.1 | 10.10.2.1) <-> server 10.10.2.2"
