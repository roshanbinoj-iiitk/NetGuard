#!/usr/bin/env python3
"""Check netguard-cli output against tcpdump, field by field.

For every packet in each pcap it compares: timestamp, ethertype, frame
length, IP addresses, protocol, ports, TCP flags, TCP/UDP payload length,
and ICMP type (for the common types tcpdump names).

    scripts/compare_tcpdump.py --cli build/netguard-cli tests/data/*.pcap

tcpdump is run as `tcpdump -nn -tt -e -r FILE`: -nn = no name/port lookups
(the -nn the brief asks for), -tt = epoch timestamps so they can be compared
as text, -e = show the Ethernet header so we can see the frame length.
Exit status is 0 only if every field of every packet matches.
"""
import argparse
import os
import re
import subprocess
import sys

TCPDUMP_LINE = re.compile(
    r"^(?P<ts>\d+\.\d+) \S+ > \S+, ethertype \S+ \((?P<etype>0x[0-9a-f]{4})\), "
    r"length (?P<len>\d+): (?P<rest>.*)$")
IP_PAIR = re.compile(
    r"^(?P<src>\d+\.\d+\.\d+\.\d+)(?:\.(?P<sport>\d+))? > "
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)(?:\.(?P<dport>\d+))?: (?P<proto_text>.*)$")
ICMP_TYPES = {"echo request": 8, "echo reply": 0, "time exceeded": 11}

NG_LINE = re.compile(
    r"^(?P<ts>\d+\.\d+) (?:"
    r"ETH ethertype=(?P<etype>0x[0-9a-f]{4})"
    r"|IPv4 (?P<proto>\S+) (?P<src>[\d.]+)(?::(?P<sport>\d+))? -> (?P<dst>[\d.]+)(?::(?P<dport>\d+))?"
    r"(?: \[(?P<flags>[^\]]+)\])?(?: type=(?P<itype>\d+) code=\d+)?"
    r")(?: ERR=(?P<err>\S+))? len=(?P<len>\d+)(?: payload=(?P<payload>\d+))?$")


def tcpdump_fields(line):
    m = TCPDUMP_LINE.match(line)
    if not m:
        return {"unparsed": line}
    f = {"ts": m["ts"], "etype": m["etype"], "len": m["len"]}
    if f["etype"] != "0x0800":
        return f
    ip = IP_PAIR.match(m["rest"])
    if not ip:
        return f
    f.update(src=ip["src"], dst=ip["dst"])
    text = ip["proto_text"]
    if ip["sport"]:
        f.update(sport=ip["sport"], dport=ip["dport"])
    if text.startswith("Flags ["):
        f["proto"] = "TCP"
        f["flags"] = re.match(r"Flags \[([^\]]*)\]", text)[1]
        f["payload"] = re.search(r", length (\d+)", text)[1]
    elif text.startswith("UDP, length"):
        f["proto"] = "UDP"
        f["payload"] = re.search(r"length (\d+)", text)[1]
    elif text.startswith("ICMP "):
        f["proto"] = "ICMP"
        for name, num in ICMP_TYPES.items():
            if text.startswith("ICMP " + name):
                f["itype"] = str(num)
    return f


def netguard_fields(line):
    m = NG_LINE.match(line)
    if not m:
        return {"unparsed": line}
    f = {"ts": m["ts"], "len": m["len"], "etype": m["etype"] or "0x0800"}
    if m["proto"]:
        f.update(proto=m["proto"], src=m["src"], dst=m["dst"])
        for key in ("sport", "dport", "flags", "itype", "payload"):
            if m[key] is not None:
                f[key] = m[key]
    return f


def is_nanosecond(path):
    with open(path, "rb") as fh:
        magic = fh.read(4)
    return magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def compare(path, cli, tcpdump):
    cmd = [tcpdump, "-nn", "-tt", "-e", "-r", path]
    if is_nanosecond(path):
        cmd.insert(1, "--time-stamp-precision=nano")
    td = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
    ng = subprocess.run([cli, "--pcap", path], capture_output=True, text=True,
                        check=True).stdout.splitlines()
    name = os.path.basename(path)
    if len(td) != len(ng):
        print(f"FAIL {name}: tcpdump printed {len(td)} packets, netguard-cli {len(ng)}")
        return False
    problems = 0
    for i, (t_line, n_line) in enumerate(zip(td, ng), start=1):
        t, n = tcpdump_fields(t_line), netguard_fields(n_line)
        # Compare every field tcpdump gave us that netguard is expected to report.
        for key, want in t.items():
            got = n.get(key)
            if got != want:
                problems += 1
                print(f"FAIL {name} packet {i}: {key}: tcpdump={want!r} netguard={got!r}")
                print(f"      tcpdump:  {t_line}\n      netguard: {n_line}")
    if problems == 0:
        print(f"OK   {name}: {len(ng)} packets, all fields match tcpdump")
    return problems == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cli", default="build/netguard-cli")
    ap.add_argument("--tcpdump", default=os.environ.get("TCPDUMP", "tcpdump"))
    ap.add_argument("pcaps", nargs="+")
    args = ap.parse_args()
    results = [compare(p, args.cli, args.tcpdump) for p in args.pcaps]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
