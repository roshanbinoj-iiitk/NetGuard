# Namespace lab

```
[client] veth-c 10.10.1.2 ── veth-fc 10.10.1.1 [fw] 10.10.2.1 veth-fs ── veth-s 10.10.2.2 [server]
```

| Script | What it does |
|---|---|
| `setup.sh` | Build the lab. Idempotent: tears down first, so it always starts clean. |
| `teardown.sh` | Kill processes in the namespaces and delete them. Safe if already gone. |
| `flush.sh` | Keep the topology, reset state: processes, nft/iptables, conntrack, ARP caches. |
| `smoke.sh` | ping + curl from client to server through fw. |
| `capture_samples.sh` | Write `icmp.pcap`, `tcp_http.pcap`, `udp.pcap` captured on `fw:veth-fc`. |
| `rootless.sh` | Run any of the above without sudo inside a throwaway user namespace. |

With root (VM): `sudo lab/setup.sh && sudo lab/smoke.sh`

Without root: `lab/rootless.sh bash -c 'lab/setup.sh && lab/smoke.sh && lab/capture_samples.sh'`
