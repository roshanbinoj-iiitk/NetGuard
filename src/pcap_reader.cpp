#include <fstream>
#include <iterator>
#include <utility>

#include "netguard/pcap.hpp"

namespace netguard {
namespace {

constexpr std::size_t kFileHeaderLen = 24;
constexpr std::size_t kRecordHeaderLen = 16;

// The magic number as it appears when read little-endian.
constexpr std::uint32_t kMagicMicro = 0xa1b2c3d4;
constexpr std::uint32_t kMagicNano = 0xa1b23c4d;
constexpr std::uint32_t kMagicMicroSwapped = 0xd4c3b2a1;
constexpr std::uint32_t kMagicNanoSwapped = 0x4d3cb2a1;

}  // namespace

bool PcapReader::fail(std::string message) {
    error_ = std::move(message);
    failed_ = true;
    return false;
}

// Header fields are stored in the byte order of the machine that wrote the
// file; the magic number told us which one that was.
std::uint32_t PcapReader::u32(FieldReader& r, std::size_t offset) const {
    return header_.big_endian ? r.be32(offset) : r.le32(offset);
}

std::uint16_t PcapReader::u16(FieldReader& r, std::size_t offset) const {
    return header_.big_endian ? r.be16(offset) : r.le16(offset);
}

bool PcapReader::open_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return fail("cannot open '" + path + "'");
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    if (in.bad()) return fail("error reading '" + path + "'");
    return open_bytes(std::move(bytes));
}

bool PcapReader::open_bytes(std::vector<std::uint8_t> bytes) {
    bytes_ = std::move(bytes);
    header_ = PcapFileHeader{};
    offset_ = 0;
    error_.clear();
    failed_ = false;

    FieldReader r(ByteView(bytes_.data(), bytes_.size()));
    // Read the magic little-endian and compare against all four spellings.
    const std::uint32_t magic = r.le32(0);
    if (!r.ok() || bytes_.size() < kFileHeaderLen) {
        return fail("file too short for a pcap header (" + std::to_string(bytes_.size()) +
                    " bytes, need 24)");
    }
    switch (magic) {
        case kMagicMicro:
            break;
        case kMagicNano:
            header_.resolution = TimestampResolution::Nano;
            break;
        case kMagicMicroSwapped:
            header_.big_endian = true;
            break;
        case kMagicNanoSwapped:
            header_.big_endian = true;
            header_.resolution = TimestampResolution::Nano;
            break;
        default:
            return fail("not a pcap file (bad magic number)");
    }

    header_.version_major = u16(r, 4);
    header_.version_minor = u16(r, 6);
    header_.thiszone = static_cast<std::int32_t>(u32(r, 8));
    header_.sigfigs = u32(r, 12);
    header_.snaplen = u32(r, 16);
    header_.linktype = u32(r, 20);

    if (header_.linktype != kLinktypeEthernet) {
        return fail("unsupported linktype " + std::to_string(header_.linktype) +
                    " (only 1 = Ethernet is supported; did you capture with -i any?)");
    }
    offset_ = kFileHeaderLen;
    return true;
}

PcapReader::Next PcapReader::next(PcapRecord& out) {
    if (failed_) return Next::Error;
    const std::size_t remaining = bytes_.size() - offset_;
    if (remaining == 0) return Next::End;

    const ByteView all(bytes_.data(), bytes_.size());
    FieldReader r(all);
    out.ts_sec = u32(r, offset_);
    out.ts_frac = u32(r, offset_ + 4);
    out.incl_len = u32(r, offset_ + 8);
    out.orig_len = u32(r, offset_ + 12);
    if (!r.ok()) {
        fail("truncated record header at offset " + std::to_string(offset_));
        return Next::Error;
    }

    if (header_.snaplen != 0 && out.incl_len > header_.snaplen) {
        fail("record at offset " + std::to_string(offset_) + " has incl_len " +
             std::to_string(out.incl_len) + " > snaplen " + std::to_string(header_.snaplen));
        return Next::Error;
    }
    const auto data = all.sub(offset_ + kRecordHeaderLen, out.incl_len);
    if (!data) {
        fail("record at offset " + std::to_string(offset_) + " has incl_len " +
             std::to_string(out.incl_len) + " but only " +
             std::to_string(remaining - kRecordHeaderLen) + " bytes remain in the file");
        return Next::Error;
    }
    out.data = *data;
    offset_ += kRecordHeaderLen + out.incl_len;
    return Next::Record;
}

}  // namespace netguard
