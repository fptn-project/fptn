/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include "common/network/ip_packet.h"

namespace fptn::filter {

using fptn::common::network::IPPacketPtr;

enum class Direction : int {
  kFromClient,
  kToClient
};


class BaseFilter {
 public:
  virtual IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const = 0;

  virtual ~BaseFilter() = default;
};

using BaseFilterSPtr = std::shared_ptr<BaseFilter>;
}  // namespace fptn::filter
