/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include "filter/filters/base_filter.h"

namespace fptn::filter {

class BitTorrent : public BaseFilter {
 public:
  BitTorrent() = default;

  ~BitTorrent() override = default;

  IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const override;
};
}  // namespace fptn::filter
