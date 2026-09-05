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

constexpr std::uint8_t kIcmpv4 = 1;
constexpr std::uint8_t kIcmpv6 = 58;
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

// ICMP echo (client -> internet) addressed to the given IP: traffic that
// carries no name, so only the address backstop can stop it.
IPPacketPtr MakeIPv4PacketTo(const std::string& dst) {
  IPPacketData p(28, 0);
  p[0] = 0x45;
  p[3] = 28;
  p[9] = kIcmpv4;
  const auto bytes =
      fptn::common::network::IPv4Address(dst).Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[16 + i] = bytes[i];
  }
  p[20] = 8;  // echo request
  return IPPacket::Parse(std::move(p));
}

IPPacketPtr MakeIPv6PacketTo(const std::string& dst) {
  IPPacketData p(48, 0);
  p[0] = 0x60;
  p[5] = 8;
  p[6] = kIcmpv6;
  const auto bytes =
      fptn::common::network::IPv6Address(dst).Get().to_v6().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[24 + i] = bytes[i];
  }
  p[40] = 128;  // echo request
  return IPPacket::Parse(std::move(p));
}

// UDP datagram (client -> internet) carrying the given payload.
IPPacketPtr MakeIPv4UdpPacketTo(
    const std::string& dst, const std::vector<std::uint8_t>& payload) {
  constexpr std::size_t kIpHdr = 20;
  constexpr std::size_t kUdpHdr = 8;

  IPPacketData p(kIpHdr + kUdpHdr + payload.size(), 0);
  p[0] = 0x45;
  p[2] = static_cast<std::uint8_t>(p.size() >> 8);
  p[3] = static_cast<std::uint8_t>(p.size() & 0xFF);
  p[9] = kUdp;
  const auto bytes =
      fptn::common::network::IPv4Address(dst).Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[16 + i] = bytes[i];
  }
  p[kIpHdr] = 0xC0;      // src port 49152
  p[kIpHdr + 2] = 0x01;  // dst port 443
  p[kIpHdr + 3] = 0xBB;
  const std::size_t udp_len = kUdpHdr + payload.size();
  p[kIpHdr + 4] = static_cast<std::uint8_t>(udp_len >> 8);
  p[kIpHdr + 5] = static_cast<std::uint8_t>(udp_len & 0xFF);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    p[kIpHdr + kUdpHdr + i] = payload[i];
  }
  return IPPacket::Parse(std::move(p));
}

// QUIC v1 Initial: long header, fixed bit, version 1, packet type 0.
IPPacketPtr MakeQuicInitialTo(const std::string& dst) {
  std::vector<std::uint8_t> payload = {
      0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94};
  payload.resize(64, 0);
  return MakeIPv4UdpPacketTo(dst, payload);
}

IPPacketPtr MakePlainTcpPacketTo(const std::string& dst) {
  constexpr std::size_t kIpHdr = 20;
  constexpr std::size_t kTcpHdr = 20;

  IPPacketData p(kIpHdr + kTcpHdr, 0);
  p[0] = 0x45;
  p[3] = static_cast<std::uint8_t>(p.size());
  p[9] = kTcp;
  const auto bytes =
      fptn::common::network::IPv4Address(dst).Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[16 + i] = bytes[i];
  }
  p[kIpHdr + 12] = 0x50;
  return IPPacket::Parse(std::move(p));
}

void PushU16(std::vector<std::uint8_t>& out, std::size_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::vector<std::uint8_t> MakeClientHello(const std::string& sni) {
  std::vector<std::uint8_t> body = {0x01, 0x00, 0x00, 0x00, 0x03, 0x03};
  body.insert(body.end(), 32, 0x11);  // random
  body.push_back(0x00);               // session id length
  PushU16(body, 2);                   // cipher suites
  body.push_back(0x13);
  body.push_back(0x01);
  body.push_back(0x01);  // compression methods
  body.push_back(0x00);

  std::vector<std::uint8_t> extensions;
  if (!sni.empty()) {
    PushU16(extensions, 0x0000);          // server_name
    PushU16(extensions, sni.size() + 5);  // extension length
    PushU16(extensions, sni.size() + 3);  // server name list length
    extensions.push_back(0x00);           // host_name
    PushU16(extensions, sni.size());
    extensions.insert(extensions.end(), sni.begin(), sni.end());
  }
  PushU16(body, extensions.size());
  body.insert(body.end(), extensions.begin(), extensions.end());

  const std::size_t handshake_len = body.size() - 4;
  body[1] = static_cast<std::uint8_t>(handshake_len >> 16);
  body[2] = static_cast<std::uint8_t>(handshake_len >> 8);
  body[3] = static_cast<std::uint8_t>(handshake_len & 0xFF);

  std::vector<std::uint8_t> record = {0x16, 0x03, 0x01};
  PushU16(record, body.size());
  record.insert(record.end(), body.begin(), body.end());
  return record;
}

// TLS handshake (client -> internet) addressed to the given IP.
IPPacketPtr MakeHandshakeTo(const std::string& dst, const std::string& sni) {
  constexpr std::size_t kIpHdr = 20;
  constexpr std::size_t kTcpHdr = 20;

  const std::vector<std::uint8_t> hello = MakeClientHello(sni);
  IPPacketData p(kIpHdr + kTcpHdr + hello.size(), 0);
  p[0] = 0x45;
  p[2] = static_cast<std::uint8_t>(p.size() >> 8);
  p[3] = static_cast<std::uint8_t>(p.size() & 0xFF);
  p[9] = kTcp;
  const auto bytes =
      fptn::common::network::IPv4Address(dst).Get().to_v4().to_bytes();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    p[16 + i] = bytes[i];
  }
  p[kIpHdr] = 0xC0;       // src port 49152
  p[kIpHdr + 2] = 0x01;   // dst port 443
  p[kIpHdr + 3] = 0xBB;
  p[kIpHdr + 12] = 0x50;  // data offset
  for (std::size_t i = 0; i < hello.size(); ++i) {
    p[kIpHdr + kTcpHdr + i] = hello[i];
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

  ASSERT_NE(filter.Apply(MakeDnsResponse("vk.ru", kTypeA, {1, 2, 3, 4}),
                Direction::kToClient),
      nullptr);

  auto out = filter.Apply(MakeDnsResponse("nn.ru", kTypeA, {195, 19, 220, 12}),
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

TEST(DomainBlacklistTest, BareTldEntryBlocksTheWholeZone) {
  const DomainBlacklist filter({"ru"});

  ASSERT_NE(filter.Apply(MakeDnsResponse("nn.ru", kTypeA, {195, 19, 220, 12}),
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

TEST(DomainBlacklistTest, BlocksHandshakeWithBlacklistedSni) {
  const DomainBlacklist filter({"ads.example.com"});

  EXPECT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "cdn.ads.example.com"),
                Direction::kFromClient),
      nullptr)
      << "The SNI is enough, the address does not have to be resolved first";
}

TEST(DomainBlacklistTest, MatchesSniCaseInsensitively) {
  const DomainBlacklist filter({"ads.example.com"});

  EXPECT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ADS.Example.COM"),
                Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, KeepsHandshakeWithAllowedSni) {
  const DomainBlacklist filter({"ads.example.com"});

  EXPECT_NE(filter.Apply(MakeHandshakeTo("1.2.3.4", "example.org"),
                Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, RemembersAddressOfBlockedHandshake) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr)
      << "ICMP carries no name, so it is blocked by the learned address";
  EXPECT_NE(filter.Apply(MakeIPv4PacketTo("8.8.8.8"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, BlocksIcmpToAddressLearnedFromDns) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, KeepsAllowedSniOnBlacklistedAddress) {
  const DomainBlacklist filter({"vk.ru"});

  ASSERT_NE(filter.Apply(MakeDnsResponse("vk.ru", kTypeA, {1, 2, 3, 4}),
                Direction::kToClient),
      nullptr);

  EXPECT_EQ(filter.Apply(MakeIPv4PacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
  EXPECT_NE(
      filter.Apply(MakeHandshakeTo("1.2.3.4", "nn.ru"), Direction::kFromClient),
      nullptr)
      << "A handshake is decided by its SNI, the address is not looked at";
}

TEST(DomainBlacklistTest, KeepsPlainTcpToBlacklistedAddress) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_NE(
      filter.Apply(MakePlainTcpPacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr)
      << "Only the handshake is dropped, not the rest of the connection";
}

TEST(DomainBlacklistTest, BlocksQuicInitialToBlacklistedAddress) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_EQ(
      filter.Apply(MakeQuicInitialTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
  EXPECT_NE(
      filter.Apply(MakeQuicInitialTo("8.8.8.8"), Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, KeepsNonQuicUdpToBlacklistedAddress) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  const std::vector<std::uint8_t> payload(64, 0x42);
  EXPECT_NE(filter.Apply(MakeIPv4UdpPacketTo("1.2.3.4", payload),
                Direction::kFromClient),
      nullptr);
}

TEST(DomainBlacklistTest, KeepsHandshakeWithoutSni) {
  const DomainBlacklist filter({"ads.example.com"});

  ASSERT_NE(
      filter.Apply(MakeDnsResponse("ads.example.com", kTypeA, {1, 2, 3, 4}),
          Direction::kToClient),
      nullptr);

  EXPECT_NE(
      filter.Apply(MakeHandshakeTo("1.2.3.4", ""), Direction::kFromClient),
      nullptr)
      << "TLS is decided by SNI, a handshake without one is not blocked";
}
