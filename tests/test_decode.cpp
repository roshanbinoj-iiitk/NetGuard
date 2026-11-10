// Hand-written packets, byte by byte, checked against the decoder.
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "netguard/format.hpp"
#include "netguard/packet.hpp"

using namespace netguard;

namespace {

using Bytes = std::vector<std::uint8_t>;

// dst MAC, src MAC, ethertype.
Bytes ethernet(std::uint16_t ethertype) {
    return {0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,  // dst 02:00:00:00:00:02
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,  // src 02:00:00:00:00:01
            static_cast<std::uint8_t>(ethertype >> 8U),
            static_cast<std::uint8_t>(ethertype)};
}

Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

Packet decode(const Bytes& b) {
    return decode_ethernet(ByteView(b.data(), b.size()));
}

std::string line(const Bytes& b) {
    PcapRecord rec;
    rec.ts_sec = 1731220000;
    rec.ts_frac = 123456;
    rec.orig_len = static_cast<std::uint32_t>(b.size());
    return format_packet_line(rec, TimestampResolution::Micro, decode(b));
}

// ICMP echo request 10.10.1.2 -> 10.10.2.2, 8-byte ICMP header, no data.
const Bytes kIcmpFrame = concat({ethernet(0x0800),
                                 {0x45, 0x00, 0x00, 0x1c,   // v4, IHL 5, total length 28
                                  0x12, 0x34, 0x00, 0x00,   // id, flags/fragment offset 0
                                  0x40, 0x01, 0x00, 0x00,   // TTL 64, proto 1 (ICMP), checksum
                                  0x0a, 0x0a, 0x01, 0x02,   // src 10.10.1.2
                                  0x0a, 0x0a, 0x02, 0x02},  // dst 10.10.2.2
                                 {0x08, 0x00, 0x00, 0x00,   // type 8 (echo request), code 0
                                  0x00, 0x01, 0x00, 0x01}});

// TCP SYN 10.10.1.2:51234 -> 10.10.2.2:80, no options.
const Bytes kSynFrame = concat({ethernet(0x0800),
                                {0x45, 0x00, 0x00, 0x28,  // total length 40
                                 0x00, 0x01, 0x40, 0x00,  // DF set, fragment offset 0
                                 0x40, 0x06, 0x00, 0x00,  // proto 6 (TCP)
                                 0x0a, 0x0a, 0x01, 0x02, 0x0a, 0x0a, 0x02, 0x02},
                                {0xc8, 0x22, 0x00, 0x50,  // ports 51234 -> 80
                                 0x00, 0x00, 0x00, 0x01,  // seq
                                 0x00, 0x00, 0x00, 0x00,  // ack
                                 0x50, 0x02,              // data offset 5, flags SYN
                                 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}});

// UDP 10.10.1.2:40000 -> 10.10.2.2:9999 carrying "hello".
const Bytes kUdpFrame = concat({ethernet(0x0800),
                                {0x45, 0x00, 0x00, 0x21,                          // total length 33
                                 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,  // proto 17
                                 0x0a, 0x0a, 0x01, 0x02, 0x0a, 0x0a, 0x02, 0x02},
                                {0x9c, 0x40, 0x27, 0x0f,  // ports 40000 -> 9999
                                 0x00, 0x0d, 0x00, 0x00,  // length 13, checksum
                                 'h', 'e', 'l', 'l', 'o'}});

}  // namespace

TEST(Decode, IcmpEchoRequest) {
    const Packet p = decode(kIcmpFrame);
    EXPECT_EQ(p.error, DecodeError::None);
    ASSERT_TRUE(p.ipv4);
    EXPECT_EQ(p.ipv4->src, 0x0a0a0102U);
    EXPECT_EQ(p.ipv4->dst, 0x0a0a0202U);
    EXPECT_EQ(p.ipv4->protocol, kProtoIcmp);
    ASSERT_TRUE(p.icmp);
    EXPECT_EQ(p.icmp->type, 8);
    EXPECT_EQ(p.icmp->code, 0);
    EXPECT_EQ(line(kIcmpFrame),
              "1731220000.123456 IPv4 ICMP 10.10.1.2 -> 10.10.2.2 type=8 code=0 len=42");
}

TEST(Decode, TcpSyn) {
    const Packet p = decode(kSynFrame);
    EXPECT_EQ(p.error, DecodeError::None);
    ASSERT_TRUE(p.tcp);
    EXPECT_EQ(p.tcp->src_port, 51234);
    EXPECT_EQ(p.tcp->dst_port, 80);
    EXPECT_EQ(p.tcp->flags, netguard::kTcpSyn);
    EXPECT_EQ(p.tcp->header_len, 20);
    EXPECT_EQ(p.tcp->payload_len, 0U);
    EXPECT_EQ(line(kSynFrame),
              "1731220000.123456 IPv4 TCP 10.10.1.2:51234 -> 10.10.2.2:80 [S] len=54 payload=0");
}

TEST(Decode, Udp) {
    const Packet p = decode(kUdpFrame);
    EXPECT_EQ(p.error, DecodeError::None);
    ASSERT_TRUE(p.udp);
    EXPECT_EQ(p.udp->src_port, 40000);
    EXPECT_EQ(p.udp->dst_port, 9999);
    EXPECT_EQ(p.udp->length, 13);
    EXPECT_EQ(p.udp->payload_len, 5U);
    EXPECT_EQ(line(kUdpFrame),
              "1731220000.123456 IPv4 UDP 10.10.1.2:40000 -> 10.10.2.2:9999 len=47 payload=5");
}

TEST(Decode, TruncatedIpv4Header) {
    // Ethernet says IPv4, but only 10 of the 20 header bytes made it.
    const Bytes frame(kSynFrame.begin(), kSynFrame.begin() + 14 + 10);
    const Packet p = decode(frame);
    EXPECT_EQ(p.error, DecodeError::TruncatedIpv4);
    EXPECT_FALSE(p.ipv4);
    EXPECT_EQ(line(frame), "1731220000.123456 ETH ethertype=0x0800 ERR=truncated-ipv4 len=24");
}

TEST(Decode, NonIpv4EthertypeIsReportedNotParsed) {
    // An ARP request: ethertype 0x0806 followed by its 28-byte body.
    Bytes arp = ethernet(0x0806);
    arp.resize(arp.size() + 28, 0);
    const Packet p = decode(arp);
    EXPECT_EQ(p.error, DecodeError::UnsupportedEthertype);
    EXPECT_EQ(p.ethertype, 0x0806);
    EXPECT_FALSE(p.ipv4);
    EXPECT_EQ(line(arp), "1731220000.123456 ETH ethertype=0x0806 len=42");
}

TEST(Decode, ShorterThanEthernetHeader) {
    const Bytes runt(kSynFrame.begin(), kSynFrame.begin() + 13);
    EXPECT_EQ(decode(runt).error, DecodeError::TruncatedEthernet);
    EXPECT_EQ(decode(Bytes{}).error, DecodeError::TruncatedEthernet);
    EXPECT_EQ(line(runt), "1731220000.123456 ERR=truncated-ethernet len=13");
}

TEST(Decode, WrongIpVersion) {
    Bytes frame = kSynFrame;
    frame[14] = 0x65;  // version 6 inside an IPv4 ethertype
    EXPECT_EQ(decode(frame).error, DecodeError::BadIpVersion);
}

TEST(Decode, IhlBelowMinimum) {
    Bytes frame = kSynFrame;
    frame[14] = 0x44;  // IHL 4 = 16 bytes, smaller than the fixed header
    EXPECT_EQ(decode(frame).error, DecodeError::BadIpHeaderLength);
}

TEST(Decode, IpOptionsCutOff) {
    Bytes frame = kSynFrame;
    frame[14] = 0x4f;  // IHL 15 = 60-byte header, but only 40 bytes of IP follow
    frame[17] = 60;    // total length 60 so only truncation is wrong
    EXPECT_EQ(decode(frame).error, DecodeError::TruncatedIpv4);
}

TEST(Decode, TruncatedTcpHeader) {
    const Bytes frame(kSynFrame.begin(), kSynFrame.end() - 5);  // 15 of 20 TCP bytes
    const Packet p = decode(frame);
    EXPECT_EQ(p.error, DecodeError::TruncatedTcp);
    ASSERT_TRUE(p.ipv4);  // the IP layer was fine and is still reported
    EXPECT_FALSE(p.tcp);
    EXPECT_EQ(line(frame),
              "1731220000.123456 IPv4 TCP 10.10.1.2 -> 10.10.2.2 ERR=truncated-tcp len=49");
}

TEST(Decode, TcpDataOffsetTooSmall) {
    Bytes frame = kSynFrame;
    frame[14 + 20 + 12] = 0x40;  // data offset 4
    EXPECT_EQ(decode(frame).error, DecodeError::BadTcpHeaderLength);
}

TEST(Decode, UdpLengthFieldTooSmall) {
    Bytes frame = kUdpFrame;
    frame[14 + 20 + 5] = 4;  // UDP length 4 < 8-byte header
    EXPECT_EQ(decode(frame).error, DecodeError::BadUdpLength);
}

TEST(Decode, TruncatedIcmp) {
    const Bytes frame(kIcmpFrame.begin(), kIcmpFrame.begin() + 14 + 20 + 1);
    EXPECT_EQ(decode(frame).error, DecodeError::TruncatedIcmp);
}

TEST(Decode, EthernetPaddingIsNotPayload) {
    Bytes frame = kUdpFrame;
    frame.resize(60, 0);  // pad to the 60-byte Ethernet minimum
    const Packet p = decode(frame);
    ASSERT_TRUE(p.udp);
    EXPECT_EQ(p.udp->payload_len, 5U);  // from the IP/UDP lengths, not the frame size
}

TEST(Decode, LaterFragmentHasNoTransportHeader) {
    Bytes frame = kUdpFrame;
    frame[14 + 7] = 0xb9;  // fragment offset 185 * 8 = 1480 bytes
    const Packet p = decode(frame);
    EXPECT_EQ(p.error, DecodeError::None);
    EXPECT_FALSE(p.udp);
    EXPECT_EQ(line(frame), "1731220000.123456 IPv4 UDP 10.10.1.2 -> 10.10.2.2 frag=1480 len=47");
}

TEST(Format, TcpFlagsUseTcpdumpLetters) {
    EXPECT_EQ(format_tcp_flags(netguard::kTcpSyn), "S");
    EXPECT_EQ(format_tcp_flags(netguard::kTcpSyn | kTcpAck), "S.");
    EXPECT_EQ(format_tcp_flags(kTcpPsh | kTcpAck), "P.");
    EXPECT_EQ(format_tcp_flags(kTcpFin | kTcpAck), "F.");
    EXPECT_EQ(format_tcp_flags(kTcpRst), "R");
    EXPECT_EQ(format_tcp_flags(0), "none");
    EXPECT_EQ(format_tcp_flags(0xff), "FSRP.UEW");
}

TEST(Format, Timestamps) {
    EXPECT_EQ(format_timestamp(1731220000, 5, TimestampResolution::Micro), "1731220000.000005");
    EXPECT_EQ(format_timestamp(1731220000, 5, TimestampResolution::Nano), "1731220000.000000005");
}

TEST(Format, Ipv4) {
    EXPECT_EQ(format_ipv4(0x0a0a0102U), "10.10.1.2");
    EXPECT_EQ(format_ipv4(0xffffffffU), "255.255.255.255");
}
