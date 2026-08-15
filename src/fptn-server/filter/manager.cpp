/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/manager.h"

#include <utility>

using fptn::common::network::IPPacketPtr;
using fptn::filter::Manager;

void Manager::Add(BaseFilterSPtr filter) noexcept {
  try {
    filters_.push_back(std::move(filter));
  } catch (const std::bad_alloc& err) {
    SPDLOG_ERROR(
        "Memory allocation failed while adding filter: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown exception occurred while adding a filter.");
  }
}

IPPacketPtr Manager::Apply(
    IPPacketPtr packet, Direction direction) const noexcept {
  for (const auto& filter : filters_) {
    packet = filter->Apply(std::move(packet), direction);
    if (!packet) {
      return nullptr;  // packet was filtered
    }
  }
  return packet;
}
