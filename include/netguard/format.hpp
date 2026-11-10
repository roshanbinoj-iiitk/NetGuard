#pragma once

#include <cstdint>
#include <string>

#include "netguard/packet.hpp"
#include "netguard/pcap.hpp"

namespace netguard {

/// "1731220000.123456" (micro) or "1731220000.123456789" (nano).
std::string format_timestamp(std::uint32_t sec, std::uint32_t frac, TimestampResolution res);

/// Dotted quad from a host-order address: 0x0a0a0102 -> "10.10.1.2".
std::string format_ipv4(std::uint32_t addr);

/// tcpdump-style flag string: SYN -> "S", SYN|ACK -> "S.", none -> "none".
std::string format_tcp_flags(std::uint8_t flags);

/// One output line (no trailing newline), e.g.
/// "1731220000.123456 IPv4 TCP 10.10.1.2:51234 -> 10.10.2.2:80 [S] len=74 payload=0"
std::string format_packet_line(const PcapRecord& rec, TimestampResolution res, const Packet& pkt);

}  // namespace netguard
