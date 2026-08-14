/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <optional>
#include <string>

#include <boost/beast/core/flat_buffer.hpp>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/protocol/payload.h"

namespace fptn::protocol::protobuf {

using protocol::BatchProtoPayload;
using protocol::ProtoPayload;
using protocol::ProtoPayloadOpt;

// DEPRECATED
ProtoPayloadOpt DeserializeIPPacket(const boost::beast::flat_buffer& buffer);
// DEPRECATED
ProtoPayloadOpt SerializeIPPacket(
    fptn::common::network::IPPacketPtr packet, bool with_padding = true);

BatchProtoPayload DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer);
ProtoPayloadOpt SerializeBatchIPPacket(
    common::network::BatchIPPacketPtr packets);

std::optional<std::string> SerializeIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6);
std::optional<std::pair<std::string, std::string>>
DeserializeIPAssignmentMessage(const std::string& message);

}  // namespace fptn::protocol::protobuf
