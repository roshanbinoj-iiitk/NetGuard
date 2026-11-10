#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <limits>

#include "netguard/byte_view.hpp"

using netguard::ByteView;

namespace {
constexpr std::array<std::uint8_t, 4> kBytes{0x12, 0x34, 0x56, 0x78};
const ByteView kView(kBytes.data(), kBytes.size());
}  // namespace

TEST(ByteView, BigEndianReads) {
    EXPECT_EQ(kView.u8(0), 0x12);
    EXPECT_EQ(kView.be16(0), 0x1234);
    EXPECT_EQ(kView.be16(2), 0x5678);
    EXPECT_EQ(kView.be32(0), 0x12345678U);
}

TEST(ByteView, LittleEndianReads) {
    EXPECT_EQ(kView.le16(0), 0x3412);
    EXPECT_EQ(kView.le32(0), 0x78563412U);
}

TEST(ByteView, ReadsPastTheEndReturnNullopt) {
    EXPECT_FALSE(kView.u8(4));
    EXPECT_FALSE(kView.be16(3));  // would need bytes 3 and 4
    EXPECT_FALSE(kView.be32(1));
    EXPECT_FALSE(ByteView().u8(0));
}

TEST(ByteView, HugeOffsetsDoNotOverflow) {
    constexpr auto kMax = std::numeric_limits<std::size_t>::max();
    EXPECT_FALSE(kView.has(kMax, 2));  // offset + len would wrap around to 1
    EXPECT_FALSE(kView.has(2, kMax));
    EXPECT_FALSE(kView.be32(kMax));
}

TEST(ByteView, SubViews) {
    const auto mid = kView.sub(1, 2);
    ASSERT_TRUE(mid);
    EXPECT_EQ(mid->size(), 2U);
    EXPECT_EQ(mid->be16(0), 0x3456);
    EXPECT_FALSE(mid->u8(2));  // a sub-view cannot see its parent's bytes
    EXPECT_FALSE(kView.sub(3, 2));
    ASSERT_TRUE(kView.from(4));
    EXPECT_TRUE(kView.from(4)->empty());
    EXPECT_FALSE(kView.from(5));
}
