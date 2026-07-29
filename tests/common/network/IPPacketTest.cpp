/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstdint>
#include <utility>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint8_t kIcmpv4 = 1;
constexpr std::uint8_t kIcmpv6 = 58;

// IPv4 packet, IHL=5 (20-byte header). For TCP/UDP the first four L4 bytes
// carry src/dst ports.
IPPacketData MakeIPv4(
    std::uint8_t proto, std::uint16_t src_port, std::uint16_t dst_port) {
  IPPacketData p(40, 0);
  p[0] = 0x45;  // version 4, IHL 5
  p[9] = proto;
  p[20] = static_cast<std::uint8_t>(src_port >> 8);
  p[21] = static_cast<std::uint8_t>(src_port & 0xFF);
  p[22] = static_cast<std::uint8_t>(dst_port >> 8);
  p[23] = static_cast<std::uint8_t>(dst_port & 0xFF);
  return p;
}

// IPv6 packet, no extension headers (L4 header at offset 40).
IPPacketData MakeIPv6(
    std::uint8_t next_header, std::uint16_t src_port, std::uint16_t dst_port) {
  IPPacketData p(60, 0);
  p[0] = 0x60;  // version 6
  p[6] = next_header;
  p[40] = static_cast<std::uint8_t>(src_port >> 8);
  p[41] = static_cast<std::uint8_t>(src_port & 0xFF);
  p[42] = static_cast<std::uint8_t>(dst_port >> 8);
  p[43] = static_cast<std::uint8_t>(dst_port & 0xFF);
  return p;
}

}  // namespace

TEST(IPPacketTest, IPv4Tcp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kTcp, 0x1234, 0x5678));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsIPv4());
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0x1234);
  EXPECT_EQ(packet->GetTcpDstPort(), 0x5678);
}

TEST(IPPacketTest, IPv4Udp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kUdp, 0x1111, 0x2222));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_TRUE(packet->IsUDP());
  EXPECT_EQ(packet->GetUdpSrcPort(), 0x1111);
  EXPECT_EQ(packet->GetUdpDstPort(), 0x2222);
}

TEST(IPPacketTest, IPv4Icmp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kIcmpv4, 0, 0));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_FALSE(packet->IsUDP());
}

TEST(IPPacketTest, IPv4TcpWithOptions) {
  // IHL=6 → 24-byte IP header, L4 header starts at offset 24.
  IPPacketData p(44, 0);
  p[0] = 0x46;  // version 4, IHL 6
  p[9] = kTcp;
  p[24] = 0x11;
  p[25] = 0x22;
  p[26] = 0x33;
  p[27] = 0x44;
  const auto packet = IPPacket::Parse(std::move(p));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0x1122);
  EXPECT_EQ(packet->GetTcpDstPort(), 0x3344);
}

TEST(IPPacketTest, IPv4TruncatedTcpReturnsZeroPort) {
  IPPacketData p(20, 0);  // IP header only, no TCP header
  p[0] = 0x45;
  p[9] = kTcp;
  const auto packet = IPPacket::Parse(std::move(p));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0);
  EXPECT_EQ(packet->GetTcpDstPort(), 0);
}

TEST(IPPacketTest, IPv6Tcp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kTcp, 0xABCD, 0xEF01));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsIPv6());
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0xABCD);
  EXPECT_EQ(packet->GetTcpDstPort(), 0xEF01);
}

TEST(IPPacketTest, IPv6Udp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kUdp, 0x3333, 0x4444));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_TRUE(packet->IsUDP());
  EXPECT_EQ(packet->GetUdpSrcPort(), 0x3333);
  EXPECT_EQ(packet->GetUdpDstPort(), 0x4444);
}

TEST(IPPacketTest, IPv6Icmp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kIcmpv6, 0, 0));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_FALSE(packet->IsUDP());
}
