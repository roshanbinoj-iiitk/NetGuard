# NetGuard
NetGuard is a C++17 Linux network security engine that captures packets, tracks connections, enforces firewall rules inline, and detects scans and floods.

## Status: week 1 - read a pcap and describe every packet

```
$ netguard-cli --pcap tests/data/tcp_http.pcap
1794294552.298690 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [S] len=74 payload=0
1794294552.298724 IPv4 TCP 10.10.2.2:80 -> 10.10.1.2:35686 [S.] len=74 payload=0
1794294552.298741 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [.] len=66 payload=0
1794294552.298836 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [P.] len=139 payload=73
...
```

## Build and test

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Requires CMake >= 3.16, a C++17 compiler (gcc or clang) and GoogleTest (system
package, or downloaded automatically). If `tcpdump` is installed, ctest also runs
`scripts/compare_tcpdump.py`, which checks every packet of every sample against
`tcpdump -nn`.

Useful options: `-DNETGUARD_SANITIZE=ON` (ASan + UBSan), `-DNETGUARD_WERROR=ON`.

## Layout

| Path | What |
|---|---|
| `include/netguard/` | Public headers: `ByteView`/`FieldReader` (bounds-checked reads), pcap reader, packet decoder, formatter |
| `src/` | Implementations and `main.cpp` (`netguard-cli`) |
| `tests/` | GoogleTest suite; `tests/data/` holds the three sample captures |
| `lab/` | Network-namespace lab (client <-> fw <-> server) - see `lab/README.md` |
| `scripts/` | `compare_tcpdump.py` field-by-field diff against tcpdump |
| `docs/` | Notes, including the output format |
