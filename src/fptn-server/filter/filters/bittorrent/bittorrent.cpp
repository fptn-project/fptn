/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/bittorrent/bittorrent.h"

#include <cstdint>
#include <cstring>

namespace {

constexpr std::uint8_t kClassic[] = {0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r',
'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};

constexpr std::uint8_t kExtensionProtocol[] = {
0x14, 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n'};

constexpr std::uint8_t kDht[] = {
'd', '1', ':', 'a', 'd', '2', ':', 'i', 'd', '2'};

bool DetectBitTorrent(const std::uint8_t* payload, std::size_t payload_size) {
  if (!payload_size) {
    return false;
  }
  const std::uint8_t first_byte = payload[0];
  // Classic Protocol
  if (first_byte == kClassic[0]) {
    constexpr std::size_t kClassicSignatureSize = sizeof(kClassic);
    return payload_size >= kClassicSignatureSize &&
           std::memcmp(payload, kClassic, kClassicSignatureSize) == 0;
  }

  // Extension Protocol
  if (first_byte == kExtensionProtocol[0]) {
    constexpr std::size_t kExtProtocolSignSize = sizeof(kExtensionProtocol);
    return payload_size >= kExtProtocolSignSize &&
           std::memcmp(payload, kExtensionProtocol, kExtProtocolSignSize) == 0;
  }

  // BT-DHT
  if (first_byte == kDht[0]) {
    constexpr std::size_t kDhtSignatureSize = sizeof(kDht);
    return payload_size >= kDhtSignatureSize &&
           std::memcmp(payload, kDht, kDhtSignatureSize) == 0;
  }
  return false;
}

}  // namespace

namespace fptn::filter {

IPPacketPtr BitTorrent::apply(IPPacketPtr packet) const {
  const auto [udp_data, udp_size] = packet->GetUdpPayload();
  if (udp_data) {
    if (DetectBitTorrent(udp_data, udp_size)) {
      return nullptr;
    }
    return packet;
  }
  const auto [tcp_data, tcp_size] = packet->GetTcpPayload();
  if (tcp_data) {
    if (DetectBitTorrent(tcp_data, tcp_size)) {
      return nullptr;
    }
    return packet;
  }
  return packet;
}

}  // namespace fptn::filter
