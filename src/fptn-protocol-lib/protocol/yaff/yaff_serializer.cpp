/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"

#include <cstring>
#include <protocol.yaff.h>  // NOLINT(build/include_order)
#include <string>
#include <utility>

#include <protocol.pb.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#ifdef FPTN_ENABLE_PACKET_PADDING
#include <algorithm>
#include <array>
#include <chrono>

#include "common/utils/utils.h"
#endif

namespace fptn::protocol::yaff {

using YaffMessage = protoyaff::fptn::protocol::Message;
using YaffMessageType = protoyaff::fptn::protocol::MessageType;

namespace {
bool HasValidYaffRootOffset(const std::uint8_t* data, std::size_t size) {
  if (size < sizeof(::yaff::Offset)) {
    return false;
  }
  ::yaff::Offset offset;
  std::memcpy(&offset, data, sizeof(offset));
  return offset < size;
}
}  // namespace

ProtoPayloadOpt SerializeBatchIPPacket(
    common::network::BatchIPPacketPtr packets) {
  if (packets.empty()) {
    return std::nullopt;
  }

  fptn::protocol::Message message;
  message.set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message.set_msg_type(fptn::protocol::MSG_BATCH_IP_PACKET);

  auto* batch = message.mutable_batch();
  for (auto& packet : packets) {
    if (!packet) {
      continue;
    }
    const auto& data = packet->Data();
    if (data.empty()) {
      continue;
    }

    fptn::protocol::Message inner;
    inner.set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
    inner.set_msg_type(fptn::protocol::MSG_IP_PACKET);
    auto* ip_packet = inner.mutable_packet();
    ip_packet->set_payload(data.data(), static_cast<int>(data.size()));

#ifdef FPTN_ENABLE_PACKET_PADDING
    if (data.size() < FPTN_IP_PACKET_MAX_SIZE) {
      // Random-length padding to obscure packet size (TLS-inside-TLS).
      constexpr std::size_t kMinPaddingBytes = 64;
      constexpr std::size_t kMaxPaddingBytes = 128;
      static const std::array<char, kMaxPaddingBytes> kPadding = [] {
        std::array<char, kMaxPaddingBytes> buf{};
        fptn::common::utils::GenerateRandomBytes(
            reinterpret_cast<std::uint8_t*>(buf.data()), buf.size());
        return buf;
      }();
      const auto ts = static_cast<std::size_t>(
          std::chrono::steady_clock::now().time_since_epoch().count());
      // Keep payload + padding within the IP packet limit (below the MTU).
      const std::size_t available = FPTN_IP_PACKET_MAX_SIZE - data.size();
      const std::size_t padding_size = std::min(
          kMinPaddingBytes + (ts % (kMaxPaddingBytes - kMinPaddingBytes)),
          available);
      ip_packet->set_padding_data(kPadding.data(), padding_size);
    }
#endif

    const auto inner_buffer = ::yaff::Serialize<YaffMessage>(inner);
    if (inner_buffer.Size() == 0) {
      continue;
    }
    batch->add_packets(inner_buffer.Data(), inner_buffer.Size());
  }

  if (batch->packets_size() == 0) {
    return std::nullopt;
  }

  const auto buffer = ::yaff::Serialize<YaffMessage>(message);
  if (buffer.Size() == 0) {
    SPDLOG_ERROR("Failed to serialize yaff BatchIPPacket");
    return std::nullopt;
  }

  ProtoPayload result(buffer.Size());
  std::memcpy(result.data(), buffer.Data(), buffer.Size());
  return result;
}

BatchProtoPayload DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer) {
  BatchProtoPayload result;
  if (buffer.size() == 0) {
    return result;
  }

  const auto* data = static_cast<const std::uint8_t*>(buffer.cdata().data());
  if (!HasValidYaffRootOffset(data, buffer.size())) {
    SPDLOG_ERROR("Malformed yaff BatchIPPacket message ({} bytes)",
        buffer.size());
    return result;
  }
  const auto& message = ::yaff::ReadMessage<YaffMessage>(data);

  if (message.msg_type() != YaffMessageType::MSG_BATCH_IP_PACKET) {
    return result;
  }

  const auto& batch = message.batch();
  result.reserve(batch.packets().size());
  for (const auto& packet : batch.packets()) {
    const auto raw = packet.AsStringView();
    if (!HasValidYaffRootOffset(
            reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size())) {
      continue;
    }
    const auto& inner = ::yaff::ReadMessage<YaffMessage>(
        reinterpret_cast<const std::uint8_t*>(raw.data()));
    if (inner.msg_type() != YaffMessageType::MSG_IP_PACKET) {
      continue;
    }
    const auto payload = inner.packet().payload().AsStringView();
    if (payload.empty()) {
      continue;
    }
    result.emplace_back(payload.begin(), payload.end());
  }
  return result;
}

std::optional<std::string> SerializeIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6) {
  fptn::protocol::Message message;
  message.set_protocol_version(1);
  message.set_msg_type(fptn::protocol::MSG_IP_ASSIGNMENT);
  auto* assignment = message.mutable_ip_addresses();
  assignment->set_address_ipv4(ip_v4);
  assignment->set_address_ipv6(ip_v6);

  const auto buffer = ::yaff::Serialize<YaffMessage>(message);
  if (buffer.Size() == 0) {
    SPDLOG_ERROR("Failed to serialize yaff IPAssignment");
    return std::nullopt;
  }
  return std::string(
      reinterpret_cast<const char*>(buffer.Data()), buffer.Size());
}

std::optional<std::pair<std::string, std::string>>
DeserializeIPAssignmentMessage(const std::string& message) {
  if (!HasValidYaffRootOffset(
          reinterpret_cast<const std::uint8_t*>(message.data()),
          message.size())) {
    SPDLOG_ERROR("Malformed yaff IPAssignment message ({} bytes)",
        message.size());
    return std::nullopt;
  }

  const auto& view = ::yaff::ReadMessage<YaffMessage>(
      reinterpret_cast<const std::uint8_t*>(message.data()));

  if (view.msg_type() != YaffMessageType::MSG_IP_ASSIGNMENT) {
    SPDLOG_ERROR("Expected MSG_IP_ASSIGNMENT");
    return std::nullopt;
  }

  const auto& assignment = view.ip_addresses();
  std::string ipv4{assignment.address_ipv4().AsStringView()};
  std::string ipv6{assignment.address_ipv6().AsStringView()};

  if (ipv4.empty() || ipv6.empty()) {
    SPDLOG_ERROR("IPv4 or IPv6 address is empty");
    return std::nullopt;
  }
  return std::make_pair(std::move(ipv4), std::move(ipv6));
}

}  // namespace fptn::protocol::yaff
