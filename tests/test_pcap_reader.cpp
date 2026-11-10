#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "netguard/format.hpp"
#include "netguard/pcap.hpp"

using namespace netguard;

namespace {

using Bytes = std::vector<std::uint8_t>;

void put32(Bytes& b, std::uint32_t v, bool big_endian) {
    for (int i = 0; i < 4; ++i) {
        const int shift = big_endian ? 24 - 8 * i : 8 * i;
        b.push_back(static_cast<std::uint8_t>(v >> static_cast<unsigned>(shift)));
    }
}

void put16(Bytes& b, std::uint16_t v, bool big_endian) {
    b.push_back(static_cast<std::uint8_t>(big_endian ? v >> 8U : v));
    b.push_back(static_cast<std::uint8_t>(big_endian ? v : v >> 8U));
}

// A pcap file built in memory: global header + any records added later.
Bytes pcap_header(std::uint32_t magic, bool big_endian, std::uint32_t snaplen = 65535,
                  std::uint32_t linktype = 1) {
    Bytes b;
    put32(b, magic, big_endian);
    put16(b, 2, big_endian);
    put16(b, 4, big_endian);
    put32(b, 0, big_endian);  // thiszone
    put32(b, 0, big_endian);  // sigfigs
    put32(b, snaplen, big_endian);
    put32(b, linktype, big_endian);
    return b;
}

void add_record(Bytes& b, std::uint32_t sec, std::uint32_t frac, const Bytes& data, bool big_endian,
                std::uint32_t orig_len = 0) {
    put32(b, sec, big_endian);
    put32(b, frac, big_endian);
    put32(b, static_cast<std::uint32_t>(data.size()), big_endian);
    put32(b, orig_len != 0 ? orig_len : static_cast<std::uint32_t>(data.size()), big_endian);
    b.insert(b.end(), data.begin(), data.end());
}

const Bytes kFrame(60, 0xab);

}  // namespace

TEST(PcapReader, LittleEndianMicroseconds) {
    // The exact bytes tcpdump writes on x86, spelled out.
    Bytes file = {0xd4, 0xc3, 0xb2, 0xa1,   // magic a1b2c3d4 stored little-endian
                  0x02, 0x00, 0x04, 0x00,   // version 2.4
                  0x00, 0x00, 0x00, 0x00,   // thiszone
                  0x00, 0x00, 0x00, 0x00,   // sigfigs
                  0x00, 0x00, 0x04, 0x00,   // snaplen 262144
                  0x01, 0x00, 0x00, 0x00};  // linktype 1
    add_record(file, 1731220000, 123456, kFrame, false, 1514);
    PcapReader r;
    ASSERT_TRUE(r.open_bytes(file)) << r.error();
    EXPECT_EQ(r.header().version_major, 2);
    EXPECT_EQ(r.header().version_minor, 4);
    EXPECT_EQ(r.header().snaplen, 262144U);
    EXPECT_FALSE(r.header().big_endian);
    EXPECT_EQ(r.header().resolution, TimestampResolution::Micro);

    PcapRecord rec;
    ASSERT_EQ(r.next(rec), PcapReader::Next::Record);
    EXPECT_EQ(rec.ts_sec, 1731220000U);
    EXPECT_EQ(rec.ts_frac, 123456U);
    EXPECT_EQ(rec.incl_len, 60U);
    EXPECT_EQ(rec.orig_len, 1514U);
    EXPECT_EQ(rec.data.size(), 60U);
    EXPECT_EQ(r.next(rec), PcapReader::Next::End);
}

TEST(PcapReader, BigEndianNanoseconds) {
    Bytes file = pcap_header(0xa1b23c4d, /*big_endian=*/true);
    add_record(file, 1731220000, 123456789, kFrame, true);
    PcapReader r;
    ASSERT_TRUE(r.open_bytes(file)) << r.error();
    EXPECT_TRUE(r.header().big_endian);
    EXPECT_EQ(r.header().resolution, TimestampResolution::Nano);
    PcapRecord rec;
    ASSERT_EQ(r.next(rec), PcapReader::Next::Record);
    EXPECT_EQ(rec.ts_frac, 123456789U);
    EXPECT_EQ(format_timestamp(rec.ts_sec, rec.ts_frac, r.header().resolution),
              "1731220000.123456789");
}

TEST(PcapReader, RejectsBadMagic) {
    Bytes file = pcap_header(0x0a0d0d0a, false);  // pcapng's magic
    PcapReader r;
    EXPECT_FALSE(r.open_bytes(file));
    EXPECT_NE(r.error().find("magic"), std::string::npos);
}

TEST(PcapReader, RejectsShortFile) {
    PcapReader r;
    EXPECT_FALSE(r.open_bytes(Bytes(10, 0)));
}

TEST(PcapReader, RejectsLinuxCookedCapture) {
    PcapReader r;
    EXPECT_FALSE(r.open_bytes(pcap_header(0xa1b2c3d4, false, 65535, 113)));
    EXPECT_NE(r.error().find("linktype 113"), std::string::npos);
}

TEST(PcapReader, RejectsInclLenAboveSnaplen) {
    Bytes file = pcap_header(0xa1b2c3d4, false, /*snaplen=*/32);
    add_record(file, 1, 0, kFrame, false);  // 60 > 32
    PcapReader r;
    ASSERT_TRUE(r.open_bytes(file));
    PcapRecord rec;
    EXPECT_EQ(r.next(rec), PcapReader::Next::Error);
    EXPECT_NE(r.error().find("snaplen"), std::string::npos);
}

TEST(PcapReader, RejectsInclLenPastEndOfFile) {
    Bytes file = pcap_header(0xa1b2c3d4, false);
    add_record(file, 1, 0, kFrame, false);
    file.resize(file.size() - 10);  // chop the last 10 bytes of packet data
    PcapReader r;
    ASSERT_TRUE(r.open_bytes(file));
    PcapRecord rec;
    EXPECT_EQ(r.next(rec), PcapReader::Next::Error);
    EXPECT_NE(r.error().find("remain"), std::string::npos);
    EXPECT_EQ(r.next(rec), PcapReader::Next::Error);  // stays failed
}

TEST(PcapReader, RejectsTruncatedRecordHeader) {
    Bytes file = pcap_header(0xa1b2c3d4, false);
    file.resize(file.size() + 7, 0);
    PcapReader r;
    ASSERT_TRUE(r.open_bytes(file));
    PcapRecord rec;
    EXPECT_EQ(r.next(rec), PcapReader::Next::Error);
}

TEST(PcapReader, MissingFile) {
    PcapReader r;
    EXPECT_FALSE(r.open_file("/nonexistent/file.pcap"));
    EXPECT_NE(r.error().find("cannot open"), std::string::npos);
}
