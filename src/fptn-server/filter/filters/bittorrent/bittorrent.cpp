/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/bittorrent/bittorrent.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "common/network/ip_utils.h"

namespace {

using fptn::common::network::ReadU16Be;

bool StartsWith(const std::uint8_t* payload,
    const std::size_t size,
    std::string_view signature) {
  return size >= signature.size() &&
         std::memcmp(payload, signature.data(), signature.size()) == 0;
}

bool IsPeerPort(const std::uint16_t port) {
  constexpr std::uint16_t kFirstPeerPort = 6881;
  constexpr std::uint16_t kLastPeerPort = 6889;

  return port >= kFirstPeerPort && port <= kLastPeerPort;
}

bool IsDht(const std::uint8_t* payload, const std::size_t size) {
  constexpr std::string_view kQuerySignature = "d1:ad2:id";
  constexpr std::string_view kResponseSignature = "d1:rd2:id";
  constexpr std::string_view kErrorSignature = "d1:eli";

  return StartsWith(payload, size, kQuerySignature) ||
         StartsWith(payload, size, kResponseSignature) ||
         StartsWith(payload, size, kErrorSignature);
}

bool IsUtpSyn(const std::uint8_t* payload, const std::size_t size) {
  constexpr std::uint8_t kSynTypeAndVersion = 0x41;
  constexpr std::uint8_t kMaxExtension = 2;
  constexpr std::size_t kAckOffset = 18;
  constexpr std::size_t kHeaderSize = kAckOffset + sizeof(std::uint16_t);

  if (size < kHeaderSize) {
    return false;
  }
  return payload[0] == kSynTypeAndVersion && payload[1] <= kMaxExtension &&
         ReadU16Be(payload + kAckOffset) == 0;
}

bool IsUdpTracker(const std::uint8_t* payload, const std::size_t size) {
  constexpr std::string_view kConnectSignature(
      "\x00\x00\x04\x17\x27\x10\x19\x80", 8);

  return StartsWith(payload, size, kConnectSignature);
}

bool IsPeerHandshake(const std::uint8_t* payload, const std::size_t size) {
  constexpr std::string_view kHandshakeSignature =
      "\x13"
      "BitTorrent protocol";

  return StartsWith(payload, size, kHandshakeSignature);
}

}  // namespace

namespace fptn::filter {

IPPacketPtr BitTorrent::Apply(IPPacketPtr packet, Direction direction) const {
  if (direction != Direction::kFromClient) {
    return packet;
  }

  if (packet->IsTCP()) {
    const auto [payload, size] = packet->GetTcpPayload();
    if (IsPeerPort(packet->GetTcpDstPort()) ||
        (payload && IsPeerHandshake(payload, size))) {
      return nullptr;
    }
  } else if (packet->IsUDP()) {
    const auto [payload, size] = packet->GetUdpPayload();
    if (IsPeerPort(packet->GetUdpDstPort()) ||
        (payload && (IsDht(payload, size) || IsUtpSyn(payload, size) ||
                        IsUdpTracker(payload, size)))) {
      return nullptr;
    }
  }
  return packet;
}

}  // namespace fptn::filter
