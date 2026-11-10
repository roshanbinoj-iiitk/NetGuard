#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace netguard {

/// A non-owning, read-only view over a run of bytes (C++17 has no std::span).
///
/// Every read is bounds-checked: asking for bytes past the end returns
/// std::nullopt instead of touching memory we do not own. Multi-byte reads
/// assemble the value with shifts, so the result never depends on the host
/// CPU's byte order or on the buffer's alignment.
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    [[nodiscard]] constexpr const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }

    /// True if [offset, offset + len) lies inside the view. Written so that
    /// offset + len can never overflow.
    [[nodiscard]] constexpr bool has(std::size_t offset, std::size_t len) const noexcept {
        return offset <= size_ && len <= size_ - offset;
    }

    [[nodiscard]] std::optional<std::uint8_t> u8(std::size_t offset) const noexcept {
        if (!has(offset, 1)) return std::nullopt;
        return at(offset);
    }

    /// Big-endian ("network byte order") 16-bit read.
    [[nodiscard]] std::optional<std::uint16_t> be16(std::size_t offset) const noexcept {
        if (!has(offset, 2)) return std::nullopt;
        return static_cast<std::uint16_t>((at(offset) << 8U) | at(offset + 1));
    }

    /// Big-endian 32-bit read.
    [[nodiscard]] std::optional<std::uint32_t> be32(std::size_t offset) const noexcept {
        if (!has(offset, 4)) return std::nullopt;
        return (std::uint32_t{at(offset)} << 24U) | (std::uint32_t{at(offset + 1)} << 16U) |
               (std::uint32_t{at(offset + 2)} << 8U) | std::uint32_t{at(offset + 3)};
    }

    /// Little-endian 16-bit read (pcap headers written on x86).
    [[nodiscard]] std::optional<std::uint16_t> le16(std::size_t offset) const noexcept {
        if (!has(offset, 2)) return std::nullopt;
        return static_cast<std::uint16_t>(at(offset) | (at(offset + 1) << 8U));
    }

    /// Little-endian 32-bit read.
    [[nodiscard]] std::optional<std::uint32_t> le32(std::size_t offset) const noexcept {
        if (!has(offset, 4)) return std::nullopt;
        return std::uint32_t{at(offset)} | (std::uint32_t{at(offset + 1)} << 8U) |
               (std::uint32_t{at(offset + 2)} << 16U) | (std::uint32_t{at(offset + 3)} << 24U);
    }

    /// Sub-view of exactly `len` bytes starting at `offset`.
    [[nodiscard]] std::optional<ByteView> sub(std::size_t offset, std::size_t len) const noexcept {
        if (!has(offset, len)) return std::nullopt;
        return ByteView(data_ + offset, len);  // NOLINT(*-pointer-arithmetic): bounds checked above
    }

    /// Sub-view from `offset` to the end.
    [[nodiscard]] std::optional<ByteView> from(std::size_t offset) const noexcept {
        if (offset > size_) return std::nullopt;
        return ByteView(data_ + offset, size_ - offset);  // NOLINT(*-pointer-arithmetic)
    }

private:
    // Only called after has() succeeded.
    [[nodiscard]] std::uint8_t at(std::size_t i) const noexcept {
        return data_[i];  // NOLINT(*-pointer-arithmetic): every caller checks bounds first
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

/// Reads several fixed-offset header fields from one ByteView with a single
/// error check at the end ("sticky" error):
///
///   FieldReader r(tcp_bytes);
///   const auto src_port = r.be16(0);
///   const auto flags = r.u8(13);
///   if (!r.ok()) return DecodeError::TruncatedTcp;
///
/// An out-of-bounds read returns 0 and marks the reader as failed, so a value
/// read past the end can never be used by accident once ok() is checked.
class FieldReader {
public:
    explicit FieldReader(ByteView view) noexcept : view_(view) {}

    [[nodiscard]] bool ok() const noexcept { return ok_; }

    std::uint8_t u8(std::size_t offset) noexcept { return take(view_.u8(offset)); }
    std::uint16_t be16(std::size_t offset) noexcept { return take(view_.be16(offset)); }
    std::uint32_t be32(std::size_t offset) noexcept { return take(view_.be32(offset)); }
    std::uint16_t le16(std::size_t offset) noexcept { return take(view_.le16(offset)); }
    std::uint32_t le32(std::size_t offset) noexcept { return take(view_.le32(offset)); }

private:
    template <typename T>
    T take(std::optional<T> value) noexcept {
        if (!value) {
            ok_ = false;
            return T{};
        }
        return *value;
    }

    ByteView view_;
    bool ok_ = true;
};

}  // namespace netguard
