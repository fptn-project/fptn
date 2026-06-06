/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/protobuf/protocol.h"

#include <algorithm>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/beast/core/flat_buffer.hpp>
#include <protocol.pb.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#ifdef DUSING_MIMALLOC
#include <mimalloc-new-delete.h>  // NOLINT(build/include_order)
#endif

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace {
class ArenaManager {
 public:
  explicit ArenaManager(std::size_t max_count = 1024)
      : max_count_(max_count),
        arena_(std::make_unique<google::protobuf::Arena>()) {}

  google::protobuf::Arena* Get() {
    if (++count_ >= max_count_) {
      count_ = 0;
      arena_->Reset();
      arena_.reset();
      arena_ = std::make_unique<google::protobuf::Arena>();
    }
    return arena_.get();
  }

 private:
  const std::size_t max_count_;
  std::size_t count_{0};
  std::unique_ptr<google::protobuf::Arena> arena_;
};

const std::vector<std::uint8_t>& RandomPaddingData() {
  static const std::vector<std::uint8_t> kRandomData = [] {
    std::vector<std::uint8_t> data(FPTN_IP_PACKET_MAX_SIZE, 0);
    fptn::common::utils::GenerateRandomBytes(data.data(), data.size());
    return data;
  }();
  return kRandomData;
}

}  // namespace

namespace fptn::protocol::protobuf {

ProtoPayloadOpt DeserializeIPPacket(const boost::beast::flat_buffer& buffer) {
  const std::size_t total_size = buffer.size();
  if (total_size == 0) {
    SPDLOG_ERROR("Failed to parse Protobuf message: empty buffer");
    return std::nullopt;
  }

  const void* data_ptr = static_cast<const char*>(buffer.cdata().data());

  // Arena optimization
  static thread_local ArenaManager arena;

  auto* message =
      google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
  if (!message->ParseFromArray(data_ptr, static_cast<int>(total_size))) {
    SPDLOG_ERROR("Failed to parse Protobuf message: parse error");
    return std::nullopt;
  }

  if (message->protocol_version() != FPTN_PROTOBUF_PROTOCOL_VERSION) {
    SPDLOG_ERROR(
        "Unsupported protocol version: {}", message->protocol_version());
    return std::nullopt;
  }

  switch (message->msg_type()) {
    case fptn::protocol::MSG_IP_PACKET:
      if (message->has_packet()) {
        const auto& payload = message->packet().payload();
        ProtoPayload result;
        result.reserve(payload.size());
        result.assign(payload.begin(), payload.end());
        return result;
      }
      SPDLOG_ERROR("Malformed IP packet: no packet field");
      break;
    case fptn::protocol::MSG_ERROR:
      if (message->has_error()) {
        SPDLOG_ERROR("Message error: {}", message->error().error_msg());
      } else {
        SPDLOG_ERROR("Malformed error message: no error field");
      }
      break;
    default:
      SPDLOG_ERROR("Unknown message type");
  }
  return std::nullopt;
}

ProtoPayloadOpt SerializeIPPacket(fptn::common::network::IPPacketPtr packet) {
  if (!packet) {
    SPDLOG_ERROR("Cannot create proto payload: packet is null");
    return std::nullopt;
  }

  // Arena optimization
  static thread_local ArenaManager arena;

  auto* message =
      google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
  message->set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message->set_msg_type(fptn::protocol::MSG_IP_PACKET);

  const auto& data = packet->Data();
  if (data.empty()) {
    SPDLOG_ERROR("Cannot create proto payload: invalid packet data");
    return std::nullopt;
  }

  message->mutable_packet()->set_payload(
      data.data(), static_cast<int>(data.size()));

  if (data.size() < FPTN_IP_PACKET_MAX_SIZE) {
    /**
     * Fill with random data to prevent issues related to TLS-inside-TLS.
     */
    constexpr std::size_t kMaxPaddingBytes = 128;
    const std::size_t available_space = FPTN_IP_PACKET_MAX_SIZE - data.size();
    const std::size_t padding_size =
        std::min(kMaxPaddingBytes, available_space);
    if (padding_size > 0) {
      const auto& padding_data = RandomPaddingData();
      message->mutable_packet()->set_padding_data(
          reinterpret_cast<const char*>(padding_data.data()), padding_size);
    }
  }
  const std::size_t estimated_size = message->ByteSizeLong();
  if (estimated_size == 0) {
    SPDLOG_ERROR("Failed to serialize Message: estimated size is 0");
    return std::nullopt;
  }

  ProtoPayload serialized_data(estimated_size);
  if (!message->SerializeToArray(
          serialized_data.data(), static_cast<int>(estimated_size))) {
    SPDLOG_ERROR("Failed to serialize Message.");
    return std::nullopt;
  }
  return serialized_data;
}

ProtoPayloadOpt SerializeBatchIPPacket(
    common::network::BatchIPPacketPtr packets) {
  if (packets.empty()) {
    return std::nullopt;
  }

  // Arena optimization
  static thread_local ArenaManager arena;

  auto* message =
      google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
  message->set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message->set_msg_type(fptn::protocol::MSG_BATCH_IP_PACKET);

  auto* batch = message->mutable_batch();

  for (auto& packet_ptr : packets) {
    if (!packet_ptr) {
      continue;
    }
    auto serialized = SerializeIPPacket(std::move(packet_ptr));
    if (serialized.has_value() && !serialized.value().empty()) {
      batch->add_packets(serialized.value().data(), serialized.value().size());
    }
  }

  if (batch->packets_size() == 0) {
    return std::nullopt;
  }

  const std::size_t estimated_size = message->ByteSizeLong();
  if (estimated_size == 0) {
    SPDLOG_ERROR("Failed to serialize BatchIPPacket: estimated size is 0");
    return std::nullopt;
  }

  ProtoPayload result(estimated_size);
  if (!message->SerializeToArray(
          result.data(), static_cast<int>(estimated_size))) {
    SPDLOG_ERROR("Failed to serialize BatchIPPacket");
    return std::nullopt;
  }

  return result;
}

BatchProtoPayload DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer) {
  BatchProtoPayload result;
  const std::size_t total_size = buffer.size();
  if (total_size == 0) {
    return result;
  }

  const auto* data = static_cast<const uint8_t*>(buffer.cdata().data());

  // Arena optimization
  static thread_local ArenaManager arena;

  auto* message =
      google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
  if (!message->ParseFromArray(data, static_cast<int>(total_size))) {
    SPDLOG_ERROR("Failed to parse BatchIPPacket message");
    return result;
  }

  if (message->msg_type() != fptn::protocol::MSG_BATCH_IP_PACKET) {
    return result;
  }

  if (!message->has_batch()) {
    SPDLOG_ERROR("BatchIPPacket message has no batch field");
    return result;
  }

  const auto& batch = message->batch();
  result.reserve(batch.packets_size());

  for (int i = 0; i < batch.packets_size(); ++i) {
    const auto& packet_data = batch.packets(i);

    fptn::protocol::Message inner_msg;
    if (!inner_msg.ParseFromString(packet_data)) {
      continue;
    }

    if (inner_msg.msg_type() == fptn::protocol::MSG_IP_PACKET &&
        inner_msg.has_packet()) {
      const auto& payload = inner_msg.packet().payload();
      ProtoPayload payload_data(payload.begin(), payload.end());
      result.emplace_back(std::move(payload_data));
    }
  }
  return result;
}

std::optional<std::string> SerializeIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6) {
  // Arena optimization
  static thread_local ArenaManager arena;

  auto* message =
      google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
  message->set_protocol_version(1);
  message->set_msg_type(fptn::protocol::MessageType::MSG_IP_ASSIGNMENT);
  auto* assignment = message->mutable_ip_addresses();
  assignment->set_address_ipv4(ip_v4);
  assignment->set_address_ipv6(ip_v6);
  std::string serialized_message;
  if (message->SerializeToString(&serialized_message)) {
    return serialized_message;
  }
  return {};
}

std::optional<std::pair<std::string, std::string>>
DeserializeIPAssignmentMessage(const std::string& message) {
  try {
    // Arena optimization
    static thread_local ArenaManager arena;

    auto* proto_message =
        google::protobuf::Arena::Create<fptn::protocol::Message>(arena.Get());
    if (!proto_message->ParseFromString(message)) {
      SPDLOG_ERROR("Failed to parse protobuf message");
      return std::nullopt;
    }

    if (proto_message->msg_type() !=
        fptn::protocol::MessageType::MSG_IP_ASSIGNMENT) {
      SPDLOG_ERROR("Expected MSG_IP_ASSIGNMENT");
      return std::nullopt;
    }

    if (!proto_message->has_ip_addresses()) {
      SPDLOG_ERROR("Message does not contain IP assignment data");
      return std::nullopt;
    }

    const auto& assignment = proto_message->ip_addresses();
    std::string ipv4 = assignment.address_ipv4();
    std::string ipv6 = assignment.address_ipv6();

    if (ipv4.empty() || ipv6.empty()) {
      SPDLOG_ERROR("IPv4 or IPv6 address is empty");
      return std::nullopt;
    }
    return std::make_pair(std::move(ipv4), std::move(ipv6));
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception while parsing IP assignment: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while parsing IP assignment");
  }
  return std::nullopt;
}

}  // namespace fptn::protocol::protobuf
