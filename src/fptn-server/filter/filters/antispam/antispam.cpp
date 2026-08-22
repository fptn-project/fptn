/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/antispam/antispam.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

bool IsMailPort(const std::uint16_t port) {
  constexpr std::uint16_t kSmtpPort = 25;
  constexpr std::uint16_t kSmtpsPort = 465;
  constexpr std::uint16_t kSubmissionPort = 587;
  constexpr std::uint16_t kSubmissionAltPort = 2525;

  return port == kSmtpPort || port == kSmtpsPort || port == kSubmissionPort ||
         port == kSubmissionAltPort;
}

bool IsAbuseTcpPort(const std::uint16_t port) {
  constexpr std::uint16_t kTelnetPort = 23;
  constexpr std::uint16_t kMsRpcPort = 135;
  constexpr std::uint16_t kFirstNetbiosPort = 137;
  constexpr std::uint16_t kLastNetbiosPort = 139;
  constexpr std::uint16_t kSmbPort = 445;

  return port == kTelnetPort || port == kMsRpcPort ||
         (port >= kFirstNetbiosPort && port <= kLastNetbiosPort) ||
         port == kSmbPort;
}

bool IsAbuseUdpPort(const std::uint16_t port) {
  constexpr std::uint16_t kNetbiosNamePort = 137;
  constexpr std::uint16_t kNetbiosDatagramPort = 138;
  constexpr std::uint16_t kSsdpPort = 1900;
  constexpr std::uint16_t kMemcachedPort = 11211;

  return port == kNetbiosNamePort || port == kNetbiosDatagramPort ||
         port == kSsdpPort || port == kMemcachedPort;
}

std::uint8_t ToUpperAscii(const std::uint8_t c) {
  constexpr std::uint8_t kCaseBit = 'a' - 'A';

  return (c >= 'a' && c <= 'z') ? static_cast<std::uint8_t>(c - kCaseBit) : c;
}

bool StartsWith(const std::uint8_t* payload,
    const std::size_t size,
    std::string_view command) {
  if (size < command.size()) {
    return false;
  }
  for (std::size_t i = 0; i < command.size(); ++i) {
    if (ToUpperAscii(payload[i]) != static_cast<std::uint8_t>(command[i])) {
      return false;
    }
  }
  return true;
}

bool IsMailCommand(const std::uint8_t* payload, const std::size_t size) {
  constexpr std::string_view kEhloCommand = "EHLO ";
  constexpr std::string_view kHeloCommand = "HELO ";
  constexpr std::string_view kMailFromCommand = "MAIL FROM:";
  constexpr std::string_view kRcptToCommand = "RCPT TO:";

  return StartsWith(payload, size, kEhloCommand) ||
         StartsWith(payload, size, kHeloCommand) ||
         StartsWith(payload, size, kMailFromCommand) ||
         StartsWith(payload, size, kRcptToCommand);
}

}  // namespace

namespace fptn::filter {

IPPacketPtr AntiSpam::Apply(IPPacketPtr packet, Direction direction) const {
  if (direction != Direction::kFromClient) {
    return packet;
  }

  if (packet->IsTCP()) {
    const std::uint16_t port = packet->GetTcpDstPort();
    const auto [payload, size] = packet->GetTcpPayload();
    if (IsMailPort(port) || IsAbuseTcpPort(port) ||
        (payload && IsMailCommand(payload, size))) {
      return nullptr;
    }
  } else if (packet->IsUDP()) {
    if (IsAbuseUdpPort(packet->GetUdpDstPort()) || packet->IsDnsMxQuery()) {
      return nullptr;
    }
  }
  return packet;
}

}  // namespace fptn::filter
