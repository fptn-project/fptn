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

#include "fptn-server/filter/filters/bittorrent/bittorrent.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;
using fptn::common::network::IPPacketPtr;
using fptn::filter::BitTorrent;
using fptn::filter::Direction;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::size_t kIpHdr = 20;
constexpr std::size_t kTcpHdr = 20;
constexpr std::size_t kUdpHdr = 8;
constexpr std::uint16_t kOrdinaryPeerPort = 51413;

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

std::string UtpPacket(std::uint8_t type_and_version) {
  std::string packet(20, '\0');
  packet[0] = static_cast<char>(type_and_version);
  return packet;
}

bool IsBlocked(const BitTorrent& filter, IPPacketPtr packet) {
  return filter.Apply(std::move(packet), Direction::kFromClient) == nullptr;
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(BitTorrentTest, BlocksPeerHandshake) {
  const BitTorrent filter;

  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(kOrdinaryPeerPort,
                                    "\x13"
                                    "BitTorrent protocol")));
}

TEST(BitTorrentTest, BlocksDhtQuery) {
  const BitTorrent filter;

  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(kOrdinaryPeerPort,
                                    "d1:ad2:id20:abcdefghij0123456789e1:q9:"
                                    "find_node1:t2:aa1:y1:qe")));
}

TEST(BitTorrentTest, BlocksDhtResponse) {
  const BitTorrent filter;

  EXPECT_TRUE(
      IsBlocked(filter, MakeUdpPacket(kOrdinaryPeerPort,
                            "d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re")))
      << "A client answering DHT queries is part of the swarm too";
}

TEST(BitTorrentTest, BlocksDhtError) {
  const BitTorrent filter;

  EXPECT_TRUE(
      IsBlocked(filter, MakeUdpPacket(kOrdinaryPeerPort,
                            "d1:eli201e23:A Generic Error Ocurrede1:y1:ee")));
}

TEST(BitTorrentTest, BlocksUdpTrackerConnect) {
  const BitTorrent filter;

  EXPECT_TRUE(IsBlocked(filter,
      MakeUdpPacket(1337, std::string_view("\x00\x00\x04\x17\x27\x10\x19\x80"
                                           "\x00\x00\x00\x00\x12\x34\x56\x78",
                              16))));
}

TEST(BitTorrentTest, BlocksUtpConnectionSetup) {
  const BitTorrent filter;

  EXPECT_TRUE(
      IsBlocked(filter, MakeUdpPacket(kOrdinaryPeerPort, UtpPacket(0x41))))
      << "Dropping ST_SYN keeps the uTP connection from ever forming";
}

TEST(BitTorrentTest, PassesEstablishedUtpPacketTypes) {
  const BitTorrent filter;

  EXPECT_FALSE(
      IsBlocked(filter, MakeUdpPacket(kOrdinaryPeerPort, UtpPacket(0x21))))
      << "Only ST_SYN is matched, the wider signature would hit other traffic";
}

TEST(BitTorrentTest, BlocksClassicPeerPortRange) {
  const BitTorrent filter;

  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(6880, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(6881, "")));
  EXPECT_TRUE(IsBlocked(filter, MakeTcpPacket(6889, "")));
  EXPECT_FALSE(IsBlocked(filter, MakeTcpPacket(6890, "")));

  EXPECT_TRUE(IsBlocked(filter, MakeUdpPacket(6881, "")));
  EXPECT_FALSE(IsBlocked(filter, MakeUdpPacket(6890, "")));
}

TEST(BitTorrentTest, IgnoresTrafficTowardsTheClient) {
  const BitTorrent filter;

  EXPECT_NE(
      filter.Apply(MakeTcpPacket(6881, ""), Direction::kToClient), nullptr)
      << "On the to-client path the port belongs to the client, not the peer";
  EXPECT_NE(filter.Apply(MakeUdpPacket(kOrdinaryPeerPort, UtpPacket(0x41)),
                Direction::kToClient),
      nullptr);
}

TEST(BitTorrentTest, PassesOrdinaryHttp) {
  const BitTorrent filter;

  EXPECT_FALSE(IsBlocked(
      filter, MakeTcpPacket(80,
                  "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n")));
}

TEST(BitTorrentTest, PassesQuic) {
  const BitTorrent filter;

  EXPECT_FALSE(IsBlocked(filter,
      MakeUdpPacket(443,
          std::string_view("\xC0\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51"
                           "\x57\x08\x00\x00\x44\x9e\x7b\x9a",
              20))))
      << "A QUIC long header must not look like uTP";
}

TEST(BitTorrentTest, PassesWireguardHandshake) {
  const BitTorrent filter;

  EXPECT_FALSE(IsBlocked(filter,
      MakeUdpPacket(kOrdinaryPeerPort,
          std::string_view("\x01\x00\x00\x00\x8b\x2c\x11\x5e\x4a\x3f\x90\x12"
                           "\x77\x1d\x60\xb4\x05\xe9\x33\xa8",
              20))));
}

TEST(BitTorrentTest, PassesDnsQuery) {
  const BitTorrent filter;

  EXPECT_FALSE(IsBlocked(filter,
      MakeUdpPacket(53,
          std::string_view("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                           "\x07"
                           "example"
                           "\x03"
                           "org"
                           "\x00\x00\x01\x00\x01",
              29))));
}
