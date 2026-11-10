#include "netguard/packet.hpp"

namespace netguard {
namespace {

constexpr std::size_t kEthernetHeaderLen = 14;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::size_t kTcpMinHeaderLen = 20;
constexpr std::size_t kUdpHeaderLen = 8;

// Each decoder fills its header into `pkt` and returns the error that stopped
// it (or None). Fields are read with explicit big-endian, bounds-checked
// accessors (FieldReader over a ByteView); nothing is ever cast onto a struct.

DecodeError decode_tcp(ByteView seg, std::uint32_t l4_len, Packet& pkt) {
    FieldReader r(seg);
    TcpHeader tcp;
    tcp.src_port = r.be16(0);
    tcp.dst_port = r.be16(2);
    tcp.header_len = static_cast<std::uint8_t>((r.u8(12) >> 4U) * 4U);  // data offset
    tcp.flags = r.u8(13);
    if (!r.ok() || !seg.has(0, kTcpMinHeaderLen)) return DecodeError::TruncatedTcp;
    if (tcp.header_len < kTcpMinHeaderLen) return DecodeError::BadTcpHeaderLength;
    tcp.payload_len = l4_len >= tcp.header_len ? l4_len - tcp.header_len : 0;
    pkt.tcp = tcp;
    // Options are not parsed yet, but they must be present in the capture.
    return seg.has(0, tcp.header_len) ? DecodeError::None : DecodeError::TruncatedTcp;
}

DecodeError decode_udp(ByteView dgram, std::uint32_t l4_len, Packet& pkt) {
    FieldReader r(dgram);
    UdpHeader udp;
    udp.src_port = r.be16(0);
    udp.dst_port = r.be16(2);
    udp.length = r.be16(4);
    if (!r.ok() || !dgram.has(0, kUdpHeaderLen)) return DecodeError::TruncatedUdp;
    if (udp.length < kUdpHeaderLen) return DecodeError::BadUdpLength;
    // Like tcpdump: trust the smaller of the UDP and IP lengths.
    const std::uint32_t len = udp.length < l4_len ? udp.length : l4_len;
    udp.payload_len = len >= kUdpHeaderLen ? len - static_cast<std::uint32_t>(kUdpHeaderLen) : 0;
    pkt.udp = udp;
    return DecodeError::None;
}

DecodeError decode_icmp(ByteView msg, Packet& pkt) {
    FieldReader r(msg);
    const IcmpHeader icmp{r.u8(0), r.u8(1)};  // type, code: all we print in week 1
    if (!r.ok()) return DecodeError::TruncatedIcmp;
    pkt.icmp = icmp;
    return DecodeError::None;
}

DecodeError decode_ipv4(ByteView ip, Packet& pkt) {
    FieldReader r(ip);
    const std::uint8_t ver_ihl = r.u8(0);
    Ipv4Header h;
    h.header_len = static_cast<std::uint8_t>((ver_ihl & 0x0FU) * 4U);  // IHL is in 32-bit words
    h.total_len = r.be16(2);
    h.frag_offset = static_cast<std::uint16_t>(r.be16(6) & 0x1FFFU);  // low 13 bits
    h.ttl = r.u8(8);
    h.protocol = r.u8(9);
    h.src = r.be32(12);
    h.dst = r.be32(16);
    if (!r.ok()) return DecodeError::TruncatedIpv4;  // fixed 20-byte header incomplete
    if ((ver_ihl >> 4U) != 4) return DecodeError::BadIpVersion;
    pkt.ipv4 = h;
    if (h.header_len < kIpv4MinHeaderLen || h.total_len < h.header_len) {
        return DecodeError::BadIpHeaderLength;
    }
    const auto l4 = ip.from(h.header_len);
    if (!l4) return DecodeError::TruncatedIpv4;  // IP options cut off

    // Later fragments carry no transport header - stop at IP.
    if (h.frag_offset != 0) return DecodeError::None;

    // Use the IP total length, not the captured length: Ethernet may pad short
    // frames, and padding is not payload.
    const std::uint32_t l4_len = std::uint32_t{h.total_len} - h.header_len;
    switch (h.protocol) {
        case kProtoTcp:
            return decode_tcp(*l4, l4_len, pkt);
        case kProtoUdp:
            return decode_udp(*l4, l4_len, pkt);
        case kProtoIcmp:
            return decode_icmp(*l4, pkt);
        default:
            return DecodeError::None;  // valid IPv4, protocol we don't parse yet
    }
}

}  // namespace

Packet decode_ethernet(ByteView frame) noexcept {
    Packet pkt;
    // Bytes 0-5 dst MAC, 6-11 src MAC, 12-13 ethertype, then the payload.
    FieldReader r(frame);
    pkt.ethertype = r.be16(12);
    const auto payload = frame.from(kEthernetHeaderLen);
    if (!r.ok() || !payload) {
        pkt.error = DecodeError::TruncatedEthernet;
    } else if (pkt.ethertype != kEthertypeIpv4) {
        pkt.error = DecodeError::UnsupportedEthertype;
    } else {
        pkt.error = decode_ipv4(*payload, pkt);
    }
    return pkt;
}

const char* to_string(DecodeError e) noexcept {
    switch (e) {
        case DecodeError::None:
            return "none";
        case DecodeError::TruncatedEthernet:
            return "truncated-ethernet";
        case DecodeError::UnsupportedEthertype:
            return "unsupported-ethertype";
        case DecodeError::TruncatedIpv4:
            return "truncated-ipv4";
        case DecodeError::BadIpVersion:
            return "bad-ip-version";
        case DecodeError::BadIpHeaderLength:
            return "bad-ip-header-length";
        case DecodeError::TruncatedTcp:
            return "truncated-tcp";
        case DecodeError::BadTcpHeaderLength:
            return "bad-tcp-header-length";
        case DecodeError::TruncatedUdp:
            return "truncated-udp";
        case DecodeError::BadUdpLength:
            return "bad-udp-length";
        case DecodeError::TruncatedIcmp:
            return "truncated-icmp";
    }
    return "unknown";
}

}  // namespace netguard
