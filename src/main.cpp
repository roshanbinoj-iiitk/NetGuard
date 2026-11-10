// netguard-cli: print one line per packet in a pcap file.
#include <iostream>
#include <string>
#include <vector>

#include "netguard/format.hpp"
#include "netguard/packet.hpp"
#include "netguard/pcap.hpp"

namespace {

void usage(std::ostream& os) {
    os << "usage: netguard-cli --pcap FILE\n"
          "\n"
          "Prints one line per packet:\n"
          "  <ts> IPv4 TCP <src>:<port> -> <dst>:<port> [<flags>] len=<wire bytes> "
          "payload=<data bytes>\n";
}

int run(const std::string& path) {
    netguard::PcapReader reader;
    if (!reader.open_file(path)) {
        std::cerr << "netguard-cli: " << path << ": " << reader.error() << '\n';
        return 1;
    }
    const auto res = reader.header().resolution;
    netguard::PcapRecord rec;
    for (;;) {
        switch (reader.next(rec)) {
            case netguard::PcapReader::Next::Record:
                std::cout << netguard::format_packet_line(rec, res,
                                                          netguard::decode_ethernet(rec.data))
                          << '\n';
                break;
            case netguard::PcapReader::Next::End:
                return 0;
            case netguard::PcapReader::Next::Error:
                std::cerr << "netguard-cli: " << path << ": " << reader.error() << '\n';
                return 1;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    const std::vector<std::string> args(argv + 1, argv + argc);  // NOLINT(*-pointer-arithmetic)
    if (args.size() == 1 && (args.at(0) == "-h" || args.at(0) == "--help")) {
        usage(std::cout);
        return 0;
    }
    if (args.size() != 2 || args.at(0) != "--pcap") {
        usage(std::cerr);
        return 2;
    }
    return run(args.at(1));
}
