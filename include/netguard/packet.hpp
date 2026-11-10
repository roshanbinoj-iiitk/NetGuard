#pragma once

#include <cstdint>
#include <optional>

#include "netguard/byte_view.hpp"

namespace netguard {

inline constexpr std::uint16_t kEthertypeIpv4 = 0x0800;
inline constexpr std::uint8_t kProtoIcmp = 1;
inline constexpr std::uint8_t kProtoTcp = 6;
inline constexpr std::uint8_t kProtoUdp = 17;

// TCP flag bits (byte 13 of the TCP header).
inline constexpr std::uint8_t kTcpFin = 0x01;
inline constexpr std::uint8_t kTcpSyn = 0x02;
inline constexpr std::uint8_t kTcpRst = 0x04;
inline constexpr std::uint8_t kTcpPsh = 0x08;
inline constexpr std::uint8_t kTcpAck = 0x10;
inline constexpr std::uint8_t kTcpUrg = 0x20;
inline constexpr std::uint8_t kTcpEce = 0x40;
inline constexpr std::uint8_t kTcpCwr = 0x80;

/// Why decoding stopped early. A malformed packet still yields a Packet;
/// the fields decoded before the problem stay filled in.
enum class DecodeError {
    None,
    TruncatedEthernet,     ///< fewer than 14 bytes
    UnsupportedEthertype,  ///< not IPv4 (ARP, IPv6, VLAN, ...) - not a bug, just out of scope
    TruncatedIpv4,         ///< fewer bytes than the 20-byte minimum or than IHL says
    BadIpVersion,          ///< version nibble is not 4
    BadIpHeaderLength,     ///< IHL < 5 or total length < header length
    TruncatedTcp,
    BadTcpHeaderLength,  ///< data offset < 5
    TruncatedUdp,
    BadUdpLength,  ///< UDP length field < 8
    TruncatedIcmp,
};

/// Short machine-friendly name, e.g. "truncated-ipv4".
const char* to_string(DecodeError e) noexcept;

struct Ipv4Header {
    std::uint8_t header_len = 0;    ///< IHL * 4, in bytes
    std::uint16_t total_len = 0;    ///< header + payload, from the header itself
    std::uint16_t frag_offset = 0;  ///< in 8-byte units; non-zero means "not the first fragment"
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint32_t src = 0;  ///< host-order value, e.g. 10.10.1.2 == 0x0a0a0102
    std::uint32_t dst = 0;
};

struct TcpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint8_t header_len = 0;  ///< data offset * 4, in bytes
    std::uint8_t flags = 0;
    std::uint32_t payload_len = 0;  ///< bytes of application data (from IP total length)
};

struct UdpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;       ///< header + payload, from the header itself
    std::uint32_t payload_len = 0;  ///< what tcpdump calls "length"
};

struct IcmpHeader {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
};

/// Everything we learned about one Ethernet frame.
struct Packet {
    std::uint16_t ethertype = 0;
    std::optional<Ipv4Header> ipv4;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;
    std::optional<IcmpHeader> icmp;
    DecodeError error = DecodeError::None;
};

/// Decode an Ethernet II frame and the IPv4/TCP/UDP/ICMP headers inside it.
/// Never reads outside `frame` and never throws.
Packet decode_ethernet(ByteView frame) noexcept;

}  // namespace netguard
