// Read the real captures from the lab (tests/data/) end to end.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "netguard/format.hpp"
#include "netguard/packet.hpp"
#include "netguard/pcap.hpp"

using namespace netguard;

namespace {

std::vector<std::string> lines_for(const std::string& name) {
    PcapReader r;
    EXPECT_TRUE(r.open_file(std::string(NETGUARD_TEST_DATA_DIR) + "/" + name)) << r.error();
    std::vector<std::string> out;
    PcapRecord rec;
    PcapReader::Next n{};
    while ((n = r.next(rec)) == PcapReader::Next::Record) {
        out.push_back(format_packet_line(rec, r.header().resolution, decode_ethernet(rec.data)));
    }
    EXPECT_EQ(n, PcapReader::Next::End) << r.error();
    return out;
}

}  // namespace

TEST(Samples, Icmp) {
    const auto lines = lines_for("icmp.pcap");
    ASSERT_EQ(lines.size(), 8U);  // 4 echo requests + 4 replies
    EXPECT_EQ(lines[0], "1794294549.626795 IPv4 ICMP 10.10.1.2 -> 10.10.2.2 type=8 code=0 len=98");
    EXPECT_EQ(lines[1], "1794294549.626826 IPv4 ICMP 10.10.2.2 -> 10.10.1.2 type=0 code=0 len=98");
}

TEST(Samples, TcpHandshakeAndHttp) {
    const auto lines = lines_for("tcp_http.pcap");
    ASSERT_EQ(lines.size(), 13U);
    EXPECT_EQ(lines[0],
              "1794294552.298690 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [S] len=74 payload=0");
    EXPECT_EQ(lines[1],
              "1794294552.298724 IPv4 TCP 10.10.2.2:80 -> 10.10.1.2:35686 [S.] len=74 payload=0");
    EXPECT_EQ(lines[2],
              "1794294552.298741 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [.] len=66 payload=0");
    EXPECT_EQ(lines[3],  // the HTTP GET
              "1794294552.298836 IPv4 TCP 10.10.1.2:35686 -> 10.10.2.2:80 [P.] len=139 payload=73");
}

TEST(Samples, Udp) {
    const auto lines = lines_for("udp.pcap");
    ASSERT_EQ(lines.size(), 6U);
    EXPECT_EQ(lines[0],
              "1794294554.372127 IPv4 UDP 10.10.1.2:35392 -> 10.10.2.2:9999 len=47 payload=5");
}
