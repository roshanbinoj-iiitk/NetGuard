# NetGuard docs

## netguard-cli output format (week 1)

One line per pcap record:

```
<ts> IPv4 TCP  <src>:<sport> -> <dst>:<dport> [<flags>] len=<wire> payload=<n>
<ts> IPv4 UDP  <src>:<sport> -> <dst>:<dport> len=<wire> payload=<n>
<ts> IPv4 ICMP <src> -> <dst> type=<t> code=<c> len=<wire>
<ts> IPv4 proto=<p> <src> -> <dst> len=<wire>          (IPv4, transport not parsed)
<ts> ETH ethertype=0x0806 len=<wire>                   (not IPv4: ARP, IPv6, VLAN...)
<ts> ... ERR=<reason> len=<wire>                        (malformed packet)
```

* `ts` - seconds.microseconds (or .nanoseconds for nanosecond pcaps), same as `tcpdump -tt`.
* `len` - frame length on the wire (pcap `orig_len`), same as tcpdump's `-e` "length".
* `payload` - TCP/UDP application bytes, same as tcpdump's per-protocol "length".
* `flags` - tcpdump letters: `F` FIN, `S` SYN, `R` RST, `P` PSH, `.` ACK, `U` URG,
  `E` ECE, `W` CWR; `none` if no flag is set.
* `frag=<bytes>` appears on non-first IPv4 fragments (no transport header to show).
* `ERR` reasons: `truncated-ethernet`, `truncated-ipv4`, `bad-ip-version`,
  `bad-ip-header-length`, `truncated-tcp`, `bad-tcp-header-length`,
  `truncated-udp`, `bad-udp-length`, `truncated-icmp`.

## Verifying against tcpdump

```
scripts/compare_tcpdump.py --cli build/netguard-cli tests/data/*.pcap
```
