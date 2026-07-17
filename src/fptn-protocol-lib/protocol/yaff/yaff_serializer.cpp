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

class YaffBatchValidator {
 public:
  YaffBatchValidator(const std::uint8_t* data, const std::uint32_t size)
      : data_(data), size_(size) {}

  bool Validate() const { return ValidateBatch(); }

 private:
  using YaffMessage = protoyaff::fptn::protocol::Message;
  using YaffBatch = protoyaff::fptn::protocol::BatchIPPacket;
  using YaffPacket = protoyaff::fptn::protocol::IPPacket;

  // Size of the yaff::FieldId (TypedLimit_) header that precedes flat fields.
  static constexpr std::uint32_t kHeaderSize = sizeof(::yaff::FieldId);
  // Width of a yaff::Offset and of a yaff::BaseArray::size_type header.
  static constexpr std::uint32_t kOffsetSize = sizeof(::yaff::Offset);
  // Bit set in TypedLimit_ for the flat layout (see yaff::FlatMessage).
  static constexpr std::uint16_t kFlatLayoutBit = 0x8000;

  // Mirrors yaff::FlatMessage::ToTypedLimit(id).
  static constexpr std::uint16_t FlatTypedLimit(const ::yaff::FieldId id) {
    return static_cast<std::uint16_t>((id << 2) | 0x8003);
  }

  // True when [pos, pos + len) lies fully inside the buffer.
  bool InBounds(const std::uint32_t pos, const std::uint32_t len) const {
    return pos <= size_ && len <= size_ - pos;
  }

  std::uint16_t ReadU16(const std::uint32_t offset) const {
    std::uint16_t value;
    std::memcpy(&value, data_ + offset, sizeof(value));
    return value;
  }

  std::uint32_t ReadU32(const std::uint32_t offset) const {
    std::uint32_t value;
    std::memcpy(&value, data_ + offset, sizeof(value));
    return value;
  }

  // Resolves a reference field of the flat message located at |message|.
  // Returns false when the frame is malformed. On success |*target| is the
  // absolute offset of the referenced object, or 0 when the field is absent
  // (yaff returns a default value and never dereferences it).
  bool ResolveField(const std::uint32_t message,
      const ::yaff::FieldId field_id,
      const ::yaff::FieldOffset field_offset,
      std::uint32_t* target) const {
    *target = 0;
    if (!InBounds(message, kHeaderSize)) {
      return false;
    }
    const std::uint16_t typed_limit = ReadU16(message);
    if ((typed_limit & kFlatLayoutBit) == 0) {
      return false;  // Not a flat message: reject (fptn never emits sparse).
    }
    if (FlatTypedLimit(field_id) >= typed_limit) {
      return true;  // Field is outside the typed limit: absent.
    }
    const std::uint32_t pointer_offset = message + kHeaderSize + field_offset;
    if (!InBounds(pointer_offset, kOffsetSize)) {
      return false;
    }
    const std::uint32_t pointer = ReadU32(pointer_offset);
    if (pointer == 0) {
      return true;  // Field not set.
    }
    if (pointer > size_ - message) {
      return false;
    }
    *target = message + pointer;
    return true;
  }

  // Validates a yaff::String / yaff::BaseArray header ([Size_][data]) located
  // at |offset| and returns the payload span.
  bool ResolveString(const std::uint32_t offset,
      std::uint32_t* data_offset,
      std::uint32_t* length) const {
    if (!InBounds(offset, kOffsetSize)) {
      return false;
    }
    *length = ReadU32(offset);
    *data_offset = offset + kOffsetSize;
    return InBounds(*data_offset, *length);
  }

  // Validates the Array<InternalOffset<String>> located at |array|: a count
  // followed by a table of offsets, each pointing to an independent packet.
  bool ValidatePacketArray(const std::uint32_t array) const {
    if (!InBounds(array, kOffsetSize)) {
      return false;
    }
    const std::uint32_t count = ReadU32(array);
    const std::uint32_t table = array + kOffsetSize;
    if (count > size_ / kOffsetSize) {
      return false;  // Implausible count: reject before touching the table.
    }
    if (!InBounds(table, count * kOffsetSize)) {
      return false;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::uint32_t element = ReadU32(table + (i * kOffsetSize));
      if (element == 0) {
        continue;  // Null element.
      }
      if (element > size_ - table) {
        return false;
      }
      std::uint32_t blob_offset = 0;
      std::uint32_t blob_length = 0;
      if (!ResolveString(table + element, &blob_offset, &blob_length)) {
        return false;
      }
      if (!YaffBatchValidator(data_ + blob_offset, blob_length)
              .ValidateInner()) {
        return false;
      }
    }
    return true;
  }

  // Outer message: root -> batch -> packets array.
  bool ValidateBatch() const {
    if (!InBounds(0, kOffsetSize)) {
      return false;
    }
    const std::uint32_t root = ReadU32(0);

    std::uint32_t batch = 0;
    if (!ResolveField(root, YaffMessage::ID_BATCH,
            protoyaff::fptn::protocol::MessageMeta::FLAT_OFFSETS
                [YaffMessage::ID_BATCH - 1],
            &batch)) {
      return false;
    }
    if (batch == 0) {
      return true;  // No batch payload: nothing to parse.
    }

    std::uint32_t array = 0;
    if (!ResolveField(batch, YaffBatch::ID_PACKETS,
            protoyaff::fptn::protocol::BatchIPPacketMeta::FLAT_OFFSETS
                [YaffBatch::ID_PACKETS - 1],
            &array)) {
      return false;
    }
    if (array == 0) {
      return true;
    }
    return ValidatePacketArray(array);
  }

  // Inner packet blob: root -> packet -> payload.
  bool ValidateInner() const {
    if (!InBounds(0, kOffsetSize)) {
      return false;
    }
    const std::uint32_t root = ReadU32(0);

    std::uint32_t packet = 0;
    if (!ResolveField(root, YaffMessage::ID_PACKET,
            protoyaff::fptn::protocol::MessageMeta::FLAT_OFFSETS
                [YaffMessage::ID_PACKET - 1],
            &packet)) {
      return false;
    }
    if (packet == 0) {
      return true;
    }

    std::uint32_t payload = 0;
    if (!ResolveField(packet, YaffPacket::ID_PAYLOAD,
            protoyaff::fptn::protocol::IPPacketMeta::FLAT_OFFSETS
                [YaffPacket::ID_PAYLOAD - 1],
            &payload)) {
      return false;
    }
    if (payload == 0) {
      return true;
    }
    std::uint32_t data_offset = 0;
    std::uint32_t length = 0;
    return ResolveString(payload, &data_offset, &length);
  }

  const std::uint8_t* data_;
  const std::uint32_t size_;
};

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
  const auto data_size = static_cast<std::uint32_t>(buffer.size());
  if (!HasValidYaffRootOffset(data, data_size)) {
    SPDLOG_ERROR(
        "Malformed yaff BatchIPPacket message ({} bytes)", buffer.size());
    return result;
  }

  if (!YaffBatchValidator(data, data_size).Validate()) {
    SPDLOG_WARN(
        "Invalid yaff BatchIPPacket, dropping ({} bytes)", buffer.size());
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
    SPDLOG_ERROR(
        "Malformed yaff IPAssignment message ({} bytes)", message.size());
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
