/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "adblock/adblock.h"

namespace fptn::adblock {
extern const unsigned char kBlocklistGz[] = {0};
extern const unsigned int kBlocklistGzLen = 0;
}  // namespace fptn::adblock

namespace {

using fptn::adblock::AdBlocker;
using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;

constexpr std::uint8_t kUdp = 17;
constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::uint16_t kTypeMx = 15;

std::vector<std::uint8_t> EncodeQName(const std::string& domain) {
  std::vector<std::uint8_t> out;
  std::size_t start = 0;
  while (start <= domain.size()) {
    std::size_t dot = domain.find('.', start);
    if (dot == std::string::npos) {
      dot = domain.size();
    }
    const std::size_t len = dot - start;
    out.push_back(static_cast<std::uint8_t>(len));
    for (std::size_t i = start; i < dot; ++i) {
      out.push_back(static_cast<std::uint8_t>(domain[i]));
    }
    if (dot == domain.size()) {
      break;
    }
    start = dot + 1;
  }
  out.push_back(0);
  return out;
}

IPPacketData MakeDnsQuery(
    const std::string& domain, std::uint16_t qtype, bool ipv6 = false) {
  std::vector<std::uint8_t> dns = {
      0x12,
      0x34,
      0x01,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
  };
  const std::vector<std::uint8_t> qname = EncodeQName(domain);
  dns.insert(dns.end(), qname.begin(), qname.end());
  dns.push_back(static_cast<std::uint8_t>(qtype >> 8));
  dns.push_back(static_cast<std::uint8_t>(qtype & 0xFF));
  dns.push_back(0x00);
  dns.push_back(0x01);

  const std::size_t ip_hdr = ipv6 ? 40 : 20;
  const std::size_t udp_len = 8 + dns.size();
  IPPacketData p(ip_hdr + udp_len, 0);

  if (ipv6) {
    p[0] = 0x60;
    p[6] = kUdp;
    p[4] = static_cast<std::uint8_t>(udp_len >> 8);
    p[5] = static_cast<std::uint8_t>(udp_len & 0xFF);
    p[8] = 0x20;
    p[24] = 0x20;
    p[39] = 0x02;
  } else {
    p[0] = 0x45;
    p[9] = kUdp;
    const std::size_t total = ip_hdr + udp_len;
    p[2] = static_cast<std::uint8_t>(total >> 8);
    p[3] = static_cast<std::uint8_t>(total & 0xFF);
    p[12] = 10;
    p[15] = 1;
    p[16] = 8;
    p[17] = 8;
    p[18] = 8;
    p[19] = 8;
  }

  const std::size_t udp = ip_hdr;
  p[udp] = 0x30;
  p[udp + 1] = 0x39;
  p[udp + 3] = 53;
  p[udp + 4] = static_cast<std::uint8_t>(udp_len >> 8);
  p[udp + 5] = static_cast<std::uint8_t>(udp_len & 0xFF);

  const std::size_t dns_off = ip_hdr + 8;
  for (std::size_t i = 0; i < dns.size(); ++i) {
    p[dns_off + i] = dns[i];
  }
  return p;
}

AdBlocker MakeBlocker() {
  return AdBlocker(
      std::unordered_set<std::string>{"doubleclick.net", "ads.example.com"});
}

std::uint8_t Rcode(const IPPacket& packet, bool ipv6 = false) {
  const std::size_t dns_off = (ipv6 ? 40 : 20) + 8;
  return packet.Data()[dns_off + 3] & 0x0F;
}

}  // namespace

TEST(AdBlockerTest, BlocksExactDomainWithLoopbackA) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);

  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
  EXPECT_EQ(resp->GetDstIPv4Address().ToString(), "10.0.0.1");
}

TEST(AdBlockerTest, BlocksSubdomainOfBlockedParent) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("a.b.ads.example.com", kTypeA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
}

TEST(AdBlockerTest, PassesThroughAllowedDomain) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("example.org", kTypeA));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}

TEST(AdBlockerTest, BlocksAaaaWithLoopbackV6) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeAAAA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const auto addrs = resp->GetDnsIPv6Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "::1");
}

TEST(AdBlockerTest, BlocksNonAddressQueryWithNxdomain) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeMx));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  EXPECT_EQ(Rcode(*resp), 3U);
}

TEST(AdBlockerTest, BlocksIpv6Query) {
  const AdBlocker blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA, true));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->IsIPv6());
  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
}

TEST(AdBlockerTest, IgnoresNonDnsPacket) {
  const AdBlocker blocker = MakeBlocker();
  IPPacketData packet = MakeDnsQuery("doubleclick.net", kTypeA);
  packet[22] = 0x01;
  packet[23] = 0x00;
  auto query = IPPacket::Parse(std::move(packet));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}

TEST(AdBlockerTest, EmptyBlocklistBlocksNothing) {
  const AdBlocker blocker{std::unordered_set<std::string>{}};
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}
