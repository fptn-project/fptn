/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <memory>
#include <string>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-server/filter/filters/antiscan/antiscan.h"

namespace {

// Builds a minimal 20-byte IPv4 header with the given destination address.
fptn::common::network::IPPacketData MakeIPv4Data(
    const fptn::common::network::IPv4Address& dst) {
  fptn::common::network::IPPacketData data(20, 0);
  data[0] = 0x45;  // version=4, IHL=5
  const auto bytes = dst.Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    data[16 + i] = bytes[i];
  }
  return data;
}

// Builds a minimal 40-byte IPv6 header with the given destination address.
fptn::common::network::IPPacketData MakeIPv6Data(
    const fptn::common::network::IPv6Address& dst) {
  fptn::common::network::IPPacketData data(40, 0);
  data[0] = 0x60;  // version=6
  const auto bytes = dst.Get().to_v6().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    data[24 + i] = bytes[i];
  }
  return data;
}

class MockIPv4Packet : public fptn::common::network::IPPacket {
 public:
  explicit MockIPv4Packet(const fptn::common::network::IPv4Address& dst)
      : fptn::common::network::IPPacket(MakeIPv4Data(dst), 0) {}

  bool IsIPv4() const noexcept override { return true; }

  bool IsIPv6() const noexcept override { return false; }
};

class MockIPv6Packet : public fptn::common::network::IPPacket {
 public:
  explicit MockIPv6Packet(const fptn::common::network::IPv6Address& dst)
      : fptn::common::network::IPPacket(MakeIPv6Data(dst), 0) {}

  bool IsIPv4() const noexcept override { return false; }

  bool IsIPv6() const noexcept override { return true; }
};

/* IPv4 */
// cppcheck-suppress syntaxError
TEST(AntiScanTest, BlockScan) {
  /* IPv4 */
  const fptn::common::network::IPv4Address server_ipv4("192.168.1.1");
  const fptn::common::network::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const fptn::common::network::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const fptn::common::network::IPv6Address net_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(net_ipv4)),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("192.168.1.5"))),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("192.168.1.255"))),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("255.255.255.255"))),
      nullptr);
}

TEST(AntiScanTest, AllowNonScanPacket) {
  /* IPv4 */
  const fptn::common::network::IPv4Address server_ipv4("192.168.1.1");
  const fptn::common::network::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const fptn::common::network::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const fptn::common::network::IPv6Address net_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_NE(
      anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(server_ipv4)),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("192.168.2.1"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("8.8.8.8"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("192.168.0.1"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                fptn::common::network::IPv4Address("192.168.0.255"))),
      nullptr);
}

/* IPv6 */
TEST(AntiScanTest, BlockScanIPv6) {
  /* IPv4 */
  const fptn::common::network::IPv4Address server_ipv4("192.168.1.1");
  const fptn::common::network::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const fptn::common::network::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const fptn::common::network::IPv6Address net_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 120;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(net_ipv6)),
      nullptr)
      << "IPv6 packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                fptn::common::network::IPv6Address(
                    "2001:0db8:85a3:0000:0000:8a2e:0370:0002"))),
      nullptr);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                fptn::common::network::IPv6Address(
                    "2001:0db8:85a3:0000:0000:8a2e:0370:00A0"))),
      nullptr);
}

TEST(AntiScanTest, AllowNonScanPacketIPv6) {
  /* IPv4 */
  const fptn::common::network::IPv4Address server_ipv4("192.168.1.1");
  const fptn::common::network::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const fptn::common::network::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const fptn::common::network::IPv6Address net_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_NE(
      anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(server_ipv6)),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                fptn::common::network::IPv6Address(
                    "2001:0db8:85a3:0000:0000:8a2e:0371:1000"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                fptn::common::network::IPv6Address(
                    "2001:0db8:85a3:0000:0000:8a2e:0370:FFFF"))),
      nullptr);
}
}  // namespace
