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

#include "fptn-server/filter/filters/adblock/adblock.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;
using fptn::common::network::IPPacketPtr;
using fptn::filter::AdBlock;
using fptn::filter::Direction;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint16_t kTypeA = 1;

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

// DNS response (resolver -> client) with a single A answer.
IPPacketPtr MakeDnsResponse(
    const std::string& domain, const std::vector<std::uint8_t>& rdata) {
  std::vector<std::uint8_t> dns = {
      0x12,
      0x34,  // id
      0x81,
      0x80,  // QR=1, RD, RA
      0x00,
      0x01,  // qdcount
      0x00,
      0x01,  // ancount
      0x00,
      0x00,  // nscount
      0x00,
      0x00,  // arcount
  };
  const std::vector<std::uint8_t> qname = EncodeQName(domain);
  dns.insert(dns.end(), qname.begin(), qname.end());
  dns.push_back(0x00);
  dns.push_back(static_cast<std::uint8_t>(kTypeA));
  dns.push_back(0x00);
  dns.push_back(0x01);  // class IN

  dns.push_back(0xC0);  // answer NAME: pointer to the question at offset 12
  dns.push_back(0x0C);
  dns.push_back(0x00);
  dns.push_back(static_cast<std::uint8_t>(kTypeA));
  dns.push_back(0x00);
  dns.push_back(0x01);  // class IN
  dns.push_back(0x00);
  dns.push_back(0x00);
  dns.push_back(0x00);
  dns.push_back(0x3C);  // ttl 60
  dns.push_back(0x00);
  dns.push_back(static_cast<std::uint8_t>(rdata.size()));
  dns.insert(dns.end(), rdata.begin(), rdata.end());

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

// UDP datagram (client -> internet) carrying the given payload.
IPPacketPtr MakeUdpPacketTo(
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
  return MakeUdpPacketTo(dst, payload);
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
TEST(AdBlockTest, BlocksHandshakeWithBlockedSni) {
  const AdBlock filter({"ads.example.com"});

  EXPECT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);
}

TEST(AdBlockTest, BlocksHandshakeOfSubdomain) {
  const AdBlock filter({"ads.example.com"});

  EXPECT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "cdn.ads.example.com"),
                Direction::kFromClient),
      nullptr);
}

TEST(AdBlockTest, KeepsHandshakeWithAllowedSni) {
  const AdBlock filter({"ads.example.com"});

  EXPECT_NE(filter.Apply(MakeHandshakeTo("1.2.3.4", "notads.example.com"),
                Direction::kFromClient),
      nullptr);
}

TEST(AdBlockTest, KeepsDnsAnswerUnchanged) {
  const AdBlock filter({"ads.example.com"});

  auto out = filter.Apply(
      MakeDnsResponse("ads.example.com", {1, 2, 3, 4}), Direction::kToClient);
  ASSERT_NE(out, nullptr);

  const auto addresses = out->GetDnsIPv4Addresses();
  ASSERT_EQ(addresses.size(), 1U);
  EXPECT_EQ(addresses[0].ToString(), "1.2.3.4")
      << "The DNS response must reach the client as the resolver sent it";
}

TEST(AdBlockTest, KeepsHandshakeToTheAddressOfABlockedDomain) {
  const AdBlock filter({"ads.example.com"});

  ASSERT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);

  EXPECT_NE(filter.Apply(MakeHandshakeTo("1.2.3.4", "allowed.example.com"),
                Direction::kFromClient),
      nullptr)
      << "The same address serves the applications the client actually uses";
}

TEST(AdBlockTest, KeepsQuicToTheAddressOfABlockedDomain) {
  const AdBlock filter({"ads.example.com"});

  ASSERT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);

  EXPECT_NE(
      filter.Apply(MakeQuicInitialTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}

TEST(AdBlockTest, KeepsPlainTrafficToTheAddressOfABlockedDomain) {
  const AdBlock filter({"ads.example.com"});

  ASSERT_EQ(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);

  const std::vector<std::uint8_t> payload(64, 0x42);
  EXPECT_NE(
      filter.Apply(MakePlainTcpPacketTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
  EXPECT_NE(
      filter.Apply(MakeUdpPacketTo("1.2.3.4", payload), Direction::kFromClient),
      nullptr);
}

TEST(AdBlockTest, KeepsEverythingWhenListIsEmpty) {
  const AdBlock filter({});

  EXPECT_NE(filter.Apply(MakeHandshakeTo("1.2.3.4", "ads.example.com"),
                Direction::kFromClient),
      nullptr);
  EXPECT_NE(
      filter.Apply(MakeQuicInitialTo("1.2.3.4"), Direction::kFromClient),
      nullptr);
}
