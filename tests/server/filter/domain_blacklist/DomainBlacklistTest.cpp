/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-server/filter/filters/domain_blacklist/domain_blacklist.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;
using fptn::common::network::IPPacketPtr;
using fptn::filter::Direction;
using fptn::filter::DomainBlacklist;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;

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

// DNS response (resolver -> client) with one A/AAAA answer per rdata entry.
IPPacketPtr MakeDnsResponse(const std::string& domain,
    std::uint16_t qtype,
    const std::vector<std::vector<std::uint8_t>>& answers) {
  std::vector<std::uint8_t> dns = {
      0x12,
      0x34,  // id
      0x81,
      0x80,  // QR=1, RD, RA
      0x00,
      0x01,  // qdcount
      0x00,
      static_cast<std::uint8_t>(answers.size()),  // ancount
      0x00,
      0x00,  // nscount
      0x00,
      0x00,  // arcount
  };
  const std::vector<std::uint8_t> qname = EncodeQName(domain);
  dns.insert(dns.end(), qname.begin(), qname.end());
  dns.push_back(static_cast<std::uint8_t>(qtype >> 8));
  dns.push_back(static_cast<std::uint8_t>(qtype & 0xFF));
  dns.push_back(0x00);
  dns.push_back(0x01);  // class IN

  for (const auto& rdata : answers) {
    dns.push_back(0xC0);  // answer NAME: pointer to the question at offset 12
    dns.push_back(0x0C);
    dns.push_back(static_cast<std::uint8_t>(qtype >> 8));
    dns.push_back(static_cast<std::uint8_t>(qtype & 0xFF));
    dns.push_back(0x00);
    dns.push_back(0x01);  // class IN
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x3C);  // ttl 60
    dns.push_back(static_cast<std::uint8_t>(rdata.size() >> 8));
    dns.push_back(static_cast<std::uint8_t>(rdata.size() & 0xFF));
    dns.insert(dns.end(), rdata.begin(), rdata.end());
  }

  constexpr std::size_t kIpHdr = 20;
  const std::size_t udp_len = 8 + dns.size();
  IPPacketData p(kIpHdr + udp_len, 0);
  p[0] = 0x45;
  const std::size_t total = kIpHdr + udp_len;
  p[2] = static_cast<std::uint8_t>(total >> 8);
  p[3] = static_cast<std::uint8_t>(total & 0xFF);
  p[9] = kUdp;
  /* src 8.8.8.8 */
  p[12] = 8;
  p[13] = 8;
  p[14] = 8;
  p[15] = 8;
  /* dst 10.0.0.2 */
  p[16] = 10;
  p[19] = 2;
  p[kIpHdr + 1] = 53;    // src port 53
  p[kIpHdr + 2] = 0x30;  // dst port 12345
  p[kIpHdr + 3] = 0x39;
  p[kIpHdr + 4] = static_cast<std::uint8_t>(udp_len >> 8);
  p[kIpHdr + 5] = static_cast<std::uint8_t>(udp_len & 0xFF);
  for (std::size_t i = 0; i < dns.size(); ++i) {
    p[kIpHdr + 8 + i] = dns[i];
  }
  return IPPacket::Parse(std::move(p));
}

IPPacketPtr MakeDnsResponse(const std::string& domain,
    std::uint16_t qtype,
    const std::vector<std::uint8_t>& rdata) {
  return MakeDnsResponse(
      domain, qtype, std::vector<std::vector<std::uint8_t>>{rdata});
}

// Plain TCP packet (client -> internet) addressed to the given IP.
IPPacketPtr MakeIPv4PacketTo(const std::string& dst) {
  IPPacketData p(20, 0);
  p[0] = 0x45;
  p[9] = kTcp;
  const auto bytes =
      fptn::common::network::IPv4Address(dst).Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[16 + i] = bytes[i];
  }
  return IPPacket::Parse(std::move(p));
}

IPPacketPtr MakeIPv6PacketTo(const std::string& dst) {
  IPPacketData p(40, 0);
  p[0] = 0x60;
  p[6] = kTcp;
  const auto bytes =
      fptn::common::network::IPv6Address(dst).Get().to_v6().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[24 + i] = bytes[i];
  }
  return IPPacket::Parse(std::move(p));
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(DomainBlacklistTest, KeepsBlacklistedAnswerUnchanged) {
  const DomainBlacklist filter({"ads.example.com"});

  auto packet = MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4});
  ASSERT_NE(packet, nullptr);

  auto out = filter.Apply(std::move(packet), Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "1.2.3.4")
      << "The DNS response must reach the client as the resolver sent it";
}

TEST(DomainBlacklistTest, KeepsBlacklistedAAAAAnswerUnchanged) {
  const DomainBlacklist filter({"ads.example.com"});

  const std::vector<std::uint8_t> rdata = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0x01};  // 2001:db8::1
  auto out = filter.Apply(MakeDnsResponse("ads.example.com", kTypeAAAA, rdata),
      Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv6Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "2001:db8::1");
}

TEST(DomainBlacklistTest, KeepsAllowedDomainAnswer) {
  const DomainBlacklist filter({"ads.example.com"});

  auto packet = MakeDnsResponse("example.org", kTypeA, {1, 2, 3, 4});
  ASSERT_NE(packet, nullptr);

  auto out = filter.Apply(std::move(packet), Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "1.2.3.4");
}

TEST(DomainBlacklistTest, BlocksSubdomainOfBlacklistedParent) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("cdn.ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, MatchesWholeLabelsOnly) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("notads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_NE(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr)
      << "A blacklist entry must match label boundaries, not any suffix";
}

TEST(DomainBlacklistTest, LeavesUnlistedDomainsOfTheSameZoneAlone) {
  const DomainBlacklist filter({"vk.ru", "mail.ru", "ya.ru"});

  // a listed neighbour of the same zone is resolved first
  ASSERT_NE(filter.Apply(MakeDnsResponse("vk.ru", kTypeA, {1, 2, 3, 4}),
                Direction::kToClient),
      nullptr);

  auto out = filter.Apply(
      MakeDnsResponse("nn.ru", kTypeA, {195, 19, 220, 12}),
      Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "195.19.220.12");

  EXPECT_NE(
      filter.Apply(MakeIPv4PacketTo("195.19.220.12"), Direction::kFromClient),
      nullptr)
      << "Only the listed domains are filtered, not the whole zone";
}

TEST(DomainBlacklistTest, LeavesSubdomainOfUnlistedDomainAlone) {
  const DomainBlacklist filter({"vk.ru", "mail.ru", "ya.ru"});

  auto out = filter.Apply(
      MakeDnsResponse("www.nn.ru", kTypeA, {195, 19, 220, 12}),
      Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "195.19.220.12");

  EXPECT_NE(
      filter.Apply(MakeIPv4PacketTo("195.19.220.12"), Direction::kFromClient),
      nullptr);
}

// Known trade-off of the address backstop: the block is by IP, so an unlisted
// domain hosted on the same address as a listed one is dropped as well.
TEST(DomainBlacklistTest, DropsTrafficToAddressSharedWithBlacklistedDomain) {
  const DomainBlacklist filter({"vk.ru"});

  ASSERT_NE(filter.Apply(MakeDnsResponse("vk.ru", kTypeA, {1, 2, 3, 4}),
                Direction::kToClient),
      nullptr);
  ASSERT_NE(filter.Apply(MakeDnsResponse("nn.ru", kTypeA, {1, 2, 3, 4}),
                Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}

// A single-label entry in the blacklist file takes the whole zone down.
TEST(DomainBlacklistTest, BareTldEntryBlocksTheWholeZone) {
  const DomainBlacklist filter({"ru"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("nn.ru", kTypeA, {195, 19, 220, 12}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(
      filter.Apply(MakeIPv4PacketTo("195.19.220.12"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, NormalizesBlacklistEntries) {
  const DomainBlacklist filter({"  ADS.Example.COM.  # tracker", "", "# note"});
  EXPECT_EQ(filter.Size(), 1U);

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("Ads.Example.Com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, RemembersEveryAnswerAddress) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(filter.Apply(MakeDnsResponse("ads.example.com", kTypeA,
                             {{1, 2, 3, 4}, {5, 6, 7, 8}}),
                Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("5.6.7.8"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, BlocksClientTrafficToResolvedIPv4) {
  const DomainBlacklist filter({"ads.example.com"});

  // the resolved address is remembered from the DNS response
  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr)
      << "Traffic to a blacklisted address should be dropped";
  EXPECT_NE(filter.Apply(MakeIPv4PacketTo("8.8.8.8"), Direction::kFromClient),
      nullptr)
      << "Traffic to any other address should pass";
}

TEST(DomainBlacklistTest, BlocksClientTrafficToResolvedIPv6) {
  const DomainBlacklist filter({"ads.example.com"});

  const std::vector<std::uint8_t> rdata = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0x01};  // 2001:db8::1
  ASSERT_NE(filter.Apply(MakeDnsResponse("ads.example.com", kTypeAAAA, rdata),
                Direction::kToClient),
      nullptr);

  EXPECT_EQ(
      filter.Apply(MakeIPv6PacketTo("2001:db8::1"), Direction::kFromClient),
      nullptr);
  EXPECT_NE(
      filter.Apply(MakeIPv6PacketTo("2001:db8::2"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, IgnoresAddressesOnToClientPath) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_NE(
      filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kToClient), nullptr)
      << "Addresses are only checked on the from-client path";
}

TEST(DomainBlacklistTest, KeepsClientDnsQueryUntouched) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  auto query = MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4});
  ASSERT_NE(query, nullptr);

  auto out = filter.Apply(std::move(query), Direction::kFromClient);
  ASSERT_NE(out, nullptr) << "The resolver address is not blacklisted";

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "1.2.3.4")
      << "DNS is not parsed on the from-client path";
}
