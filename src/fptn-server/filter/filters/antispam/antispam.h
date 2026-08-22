/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include "filter/filters/base_filter.h"

namespace fptn::filter {

class AntiSpam final : public BaseFilter {
 public:
  AntiSpam() = default;

  IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const override;

  ~AntiSpam() override = default;
};
}  // namespace fptn::filter
