/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "fptn-server/filter/filters/antispam/antispam.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;
using fptn::common::network::IPPacketPtr;
using fptn::filter::AntiSpam;
using fptn::filter::Direction;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::size_t kIpHdr = 20;
constexpr std::size_t kTcpHdr = 20;
constexpr std::size_t kUdpHdr = 8;

void FillIPv4Header(IPPacketData& p, std::uint8_t protocol) {
  p[0] = 0x45;
  p[2] = static_cast<std::uint8_t>(p.size() >> 8);
  p[3] = static_cast<std::uint8_t>(p.size() & 0xFF);
  p[9] = protocol;
  /* src 10.0.0.2 */
  p[12] = 10;
  p[15] = 2;
  /* dst 93.184.216.34 */
  p[16] = 93;
  p[17] = 184;
  p[18] = 216;
  p[19] = 34;
}

IPPacketPtr MakeTcpPacket(std::uint16_t dst_port, std::string_view payload) {
  IPPacketData p(kIpHdr + kTcpHdr + payload.size(), 0);
  FillIPv4Header(p, kTcp);
  p[kIpHdr + 2] = static_cast<std::uint8_t>(dst_port >> 8);
  p[kIpHdr + 3] = static_cast<std::uint8_t>(dst_port & 0xFF);
  p[kIpHdr + 12] = static_cast<std::uint8_t>((kTcpHdr / 4) << 4);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    p[kIpHdr + kTcpHdr + i] = static_cast<std::uint8_t>(payload[i]);
  }
  return IPPacket::Parse(std::move(p));
}

IPPacketPtr MakeUdpPacket(std::uint16_t dst_port, std::string_view payload) {
  IPPacketData p(kIpHdr + kUdpHdr + payload.size(), 0);
  FillIPv4Header(p, kUdp);
  p[kIpHdr + 2] = static_cast<std::uint8_t>(dst_port >> 8);
  p[kIpHdr + 3] = static_cast<std::uint8_t>(dst_port & 0xFF);
  const std::size_t udp_len = kUdpHdr + payload.size();
  p[kIpHdr + 4] = static_cast<std::uint8_t>(udp_len >> 8);
  p[kIpHdr + 5] = static_cast<std::uint8_t>(udp_len & 0xFF);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    p[kIpHdr + kUdpHdr + i] = static_cast<std::uint8_t>(payload[i]);
  }
  return IPPacket::Parse(std::move(p));
}

bool IsBlocked(const AntiSpam& filter, IPPacketPtr packet) {
  return filter.Apply(std::move(packet), Direction::kFromClient) == nullptr;
}

std::string DnsQuery(const std::string& domain, std::uint16_t qtype) {
  std::string dns("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12);
  std::size_t start = 0;
  while (start <= domain.size()) {
    std::size_t dot = domain.find('.', start);
    if (dot == std::string::npos) {
      dot = domain.size();
    }
    dns += static_cast<char>(dot - start);
    dns += domain.substr(start, dot - start);
    if (dot == domain.size()) {
      break;
    }
    start = dot + 1;
  }
  dns += '\0';
  dns += static_cast<char>(qtype >> 8);
  dns += static_cast<char>(qtype & 0xFF);
  dns += '\0';
  dns += '\x01';
  return dns;
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(AntiSpamTest, BlocksDirectToMxPort) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(25, "")))
      << "Port 25 is how bots deliver straight to the recipient MX";
}

TEST(AntiSpamTest, BlocksSubmissionPorts) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(465, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(587, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(2525, "")));
}

TEST(AntiSpamTest, BlocksSmtpGreetingOnAnyPort) {
  const AntiSpam filter;

  EXPECT_TRUE(
      IsBlocked(filter, MakeTcpPacket(8025, "EHLO mail.example.com\r\n")))
      << "A relay on a non-standard port must be caught by the payload";
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(2526, "HELO example.com\r\n")));
}

TEST(AntiSpamTest, BlocksSmtpEnvelopeCommands) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(
      filter, MakeTcpPacket(8025, "MAIL FROM:<bot@example.com>\r\n")));
  EXPECT_TRUE(IsBlocked(
      filter, MakeTcpPacket(8025, "RCPT TO:<victim@example.org>\r\n")));
}

TEST(AntiSpamTest, MatchesSmtpCommandsRegardlessOfCase) {
  const AntiSpam filter;

  EXPECT_TRUE(
      IsBlocked(filter, MakeTcpPacket(8025, "ehlo mail.example.com\r\n")))
      << "SMTP verbs are case-insensitive, so lowercase must not evade";
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(8025, "Mail From:<a@b.c>\r\n")));
}

TEST(AntiSpamTest, BlocksTelnetAndSmb) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(23, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(135, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(445, "")));
}

TEST(AntiSpamTest, BlocksNetbiosRange) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(136, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(137, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(138, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(139, "")));
  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(140, "")));
}

TEST(AntiSpamTest, BlocksReflectorPorts) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(137, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(138, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(1900, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(11211, "")));
}

TEST(AntiSpamTest, PassesOrdinaryTraffic) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(443, "\x16\x03\x01 hello")));
  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(80, "GET / HTTP/1.1\r\n")));
  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(22, "SSH-2.0-OpenSSH_9.6\r\n")));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, "")));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(443, "")));
}

TEST(AntiSpamTest, PassesPayloadThatOnlyMentionsAnSmtpCommand) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(80, "GET /ehlo HTTP/1.1\r\n")))
      << "Only a payload that starts with the command is an SMTP session";
}

TEST(AntiSpamTest, BlocksMxLookup) {
  const AntiSpam filter;

  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(53, DnsQuery("gmail.com", 15))))
      << "Only a bot resolves MX before delivering straight to the recipient";
}

TEST(AntiSpamTest, BlocksRealMxLookupFromDig) {
  const AntiSpam filter;

  const std::string query(
      "\x1a\x2b"
      "\x01\x20"
      "\x00\x01"
      "\x00\x00"
      "\x00\x00"
      "\x00\x01"
      "\x05"
      "gmail"
      "\x03"
      "com"
      "\x00"
      "\x00\x0f"
      "\x00\x01"
      "\x00"
      "\x00\x29"
      "\x04\xd0"
      "\x00\x00\x00\x00"
      "\x00\x00",
      38);

  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(53, query)));
}

TEST(AntiSpamTest, PassesRealALookupFromDig) {
  const AntiSpam filter;

  const std::string query(
      "\x1a\x2b"
      "\x01\x20"
      "\x00\x01"
      "\x00\x00"
      "\x00\x00"
      "\x00\x01"
      "\x05"
      "gmail"
      "\x03"
      "com"
      "\x00"
      "\x00\x01"
      "\x00\x01"
      "\x00"
      "\x00\x29"
      "\x04\xd0"
      "\x00\x00\x00\x00"
      "\x00\x00",
      38);

  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, query)));
}

TEST(AntiSpamTest, PassesOrdinaryDnsLookups) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, DnsQuery("gmail.com", 1))));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, DnsQuery("gmail.com", 28))));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, DnsQuery("gmail.com", 65))));
}

TEST(AntiSpamTest, LooksForMxOnPortFiftyThreeOnly) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(5353, DnsQuery("a.local", 15))));
}

TEST(AntiSpamTest, IgnoresMalformedDns) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, "")));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, std::string(8, '\xFF'))));

  const std::string truncated =
      std::string("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12) +
      std::string(24, '\xFF');
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(53, truncated)));
}

TEST(AntiSpamTest, IgnoresTrafficTowardsTheClient) {
  const AntiSpam filter;

  EXPECT_NE(filter.Apply(MakeTcpPacket(25, ""), Direction::kToClient), nullptr)
      << "On the to-client path the port belongs to the client, not the peer";
  EXPECT_NE(
      filter.Apply(MakeTcpPacket(445, ""), Direction::kToClient), nullptr);
  EXPECT_NE(filter.Apply(MakeUdpPacket(53, DnsQuery("gmail.com", 15)),
                Direction::kToClient),
      nullptr);
}

TEST(AntiSpamTest, LooksForMailOnTcpOnly) {
  const AntiSpam filter;

  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(25, "EHLO example.com\r\n")))
      << "Mail is a TCP protocol, so UDP carries no session to block";
}
