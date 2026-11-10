#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "netguard/byte_view.hpp"

namespace netguard {

/// Link-layer type 1 (LINKTYPE_ETHERNET / DLT_EN10MB). The only one we accept in week 1.
inline constexpr std::uint32_t kLinktypeEthernet = 1;

enum class TimestampResolution { Micro, Nano };

/// The 24-byte global header at the start of every classic pcap file.
struct PcapFileHeader {
    std::uint16_t version_major = 0;
    std::uint16_t version_minor = 0;
    std::int32_t thiszone = 0;
    std::uint32_t sigfigs = 0;
    std::uint32_t snaplen = 0;
    std::uint32_t linktype = 0;
    TimestampResolution resolution = TimestampResolution::Micro;
    bool big_endian = false;  ///< true if the file was written big-endian
};

/// One packet record: 16-byte header + the captured bytes.
struct PcapRecord {
    std::uint32_t ts_sec = 0;
    std::uint32_t ts_frac = 0;   ///< microseconds or nanoseconds, see PcapFileHeader::resolution
    std::uint32_t incl_len = 0;  ///< bytes actually saved in the file
    std::uint32_t orig_len = 0;  ///< bytes the packet had on the wire
    ByteView data;               ///< points into the reader's buffer (incl_len bytes)
};

/// Reads a classic libpcap file held entirely in memory.
///
///   PcapReader r;
///   if (!r.open_file(path)) { print r.error(); }
///   PcapRecord rec;
///   while (r.next(rec) == PcapReader::Next::Record) { ... }
class PcapReader {
public:
    enum class Next { Record, End, Error };

    /// Load and validate a file. Returns false and sets error() on failure.
    bool open_file(const std::string& path);
    /// Same, from bytes already in memory (used by tests).
    bool open_bytes(std::vector<std::uint8_t> bytes);

    /// Read the next record. On Next::Error, error() says why; reading stops there.
    Next next(PcapRecord& out);

    [[nodiscard]] const PcapFileHeader& header() const noexcept { return header_; }
    [[nodiscard]] const std::string& error() const noexcept { return error_; }

private:
    bool fail(std::string message);
    std::uint32_t u32(FieldReader& r, std::size_t offset) const;
    std::uint16_t u16(FieldReader& r, std::size_t offset) const;

    std::vector<std::uint8_t> bytes_;
    PcapFileHeader header_;
    std::size_t offset_ = 0;
    std::string error_;
    bool failed_ = false;
};

}  // namespace netguard
