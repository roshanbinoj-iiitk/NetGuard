#include "netguard/format.hpp"

#include <array>

namespace netguard {

std::string format_timestamp(std::uint32_t sec, std::uint32_t frac, TimestampResolution res) {
    // The fraction is zero-padded: 5 us -> ".000005", 5 ns -> ".000000005".
    const std::size_t digits = res == TimestampResolution::Nano ? 9 : 6;
    std::string fraction = std::to_string(frac);
    if (fraction.size() < digits) fraction.insert(0, digits - fraction.size(), '0');
    return std::to_string(sec) + "." + fraction;
}

std::string format_ipv4(std::uint32_t addr) {
    return std::to_string((addr >> 24U) & 0xFFU) + "." + std::to_string((addr >> 16U) & 0xFFU) +
           "." + std::to_string((addr >> 8U) & 0xFFU) + "." + std::to_string(addr & 0xFFU);
}

std::string format_tcp_flags(std::uint8_t flags) {
    // Same letters and order as tcpdump's print-tcp.c, so output lines up.
    struct Flag {
        std::uint8_t bit;
        char letter;
    };
    constexpr std::array<Flag, 8> kFlags{{{kTcpFin, 'F'},
                                          {kTcpSyn, 'S'},
                                          {kTcpRst, 'R'},
                                          {kTcpPsh, 'P'},
                                          {kTcpAck, '.'},
                                          {kTcpUrg, 'U'},
                                          {kTcpEce, 'E'},
                                          {kTcpCwr, 'W'}}};
    std::string out;
    for (const auto& f : kFlags) {
        if ((flags & f.bit) != 0) out += f.letter;
    }
    return out.empty() ? "none" : out;
}

namespace {

const char* protocol_name(std::uint8_t proto) {
    switch (proto) {
        case kProtoIcmp:
            return "ICMP";
        case kProtoTcp:
            return "TCP";
        case kProtoUdp:
            return "UDP";
        default:
            return nullptr;
    }
}

// 0x0806 -> "0x0806"
std::string hex16(std::uint16_t v) {
    constexpr std::array<char, 16> kDigits{'0', '1', '2', '3', '4', '5', '6', '7',
                                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out = "0x";
    for (unsigned shift = 12;; shift -= 4) {
        out += kDigits.at((unsigned{v} >> shift) & 0xFU);
        if (shift == 0) break;
    }
    return out;
}

std::string endpoint(std::uint32_t addr, std::uint16_t port) {
    return format_ipv4(addr) + ":" + std::to_string(port);
}

}  // namespace

std::string format_packet_line(const PcapRecord& rec, TimestampResolution res, const Packet& pkt) {
    std::string line = format_timestamp(rec.ts_sec, rec.ts_frac, res);
    const std::string len = " len=" + std::to_string(rec.orig_len);

    if (pkt.error == DecodeError::TruncatedEthernet) {
        return line + " ERR=" + to_string(pkt.error) + len;
    }
    if (!pkt.ipv4) {
        const bool unsupported = pkt.error == DecodeError::UnsupportedEthertype;
        return line + " ETH ethertype=" + hex16(pkt.ethertype) +
               (unsupported ? std::string() : std::string(" ERR=") + to_string(pkt.error)) + len;
    }

    const Ipv4Header& ip = *pkt.ipv4;
    line += " IPv4 ";
    if (const char* name = protocol_name(ip.protocol)) {
        line += name;
    } else {
        line += "proto=" + std::to_string(ip.protocol);
    }

    if (pkt.tcp) {
        line += " " + endpoint(ip.src, pkt.tcp->src_port) + " -> " +
                endpoint(ip.dst, pkt.tcp->dst_port) + " [" + format_tcp_flags(pkt.tcp->flags) + "]";
    } else if (pkt.udp) {
        line += " " + endpoint(ip.src, pkt.udp->src_port) + " -> " +
                endpoint(ip.dst, pkt.udp->dst_port);
    } else {
        line += " " + format_ipv4(ip.src) + " -> " + format_ipv4(ip.dst);
        if (pkt.icmp) {
            line += " type=" + std::to_string(pkt.icmp->type) +
                    " code=" + std::to_string(pkt.icmp->code);
        }
        if (ip.frag_offset != 0) line += " frag=" + std::to_string(ip.frag_offset * 8U);
    }

    if (pkt.error != DecodeError::None) line += std::string(" ERR=") + to_string(pkt.error);
    line += len;
    if (pkt.error == DecodeError::None) {
        if (pkt.tcp) line += " payload=" + std::to_string(pkt.tcp->payload_len);
        if (pkt.udp) line += " payload=" + std::to_string(pkt.udp->payload_len);
    }
    return line;
}

}  // namespace netguard
