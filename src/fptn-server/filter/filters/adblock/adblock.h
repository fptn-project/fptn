/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "filter/filters/base_filter.h"

namespace fptn::filter {

/**
 * @class AdBlock
 * @brief Blocks ad and tracker domains by the SNI of their TLS handshake.
 * Nothing else is matched: the addresses those domains resolve to are shared
 * with the services the client actually uses.
 */
class AdBlock final : public BaseFilter {
 public:
  AdBlock(const std::filesystem::path& data_dir,
      const std::vector<std::string>& urls);

  explicit AdBlock(const std::vector<std::string>& domains);

  AdBlock(const AdBlock&) = delete;
  AdBlock& operator=(const AdBlock&) = delete;

  IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const override;

  ~AdBlock() override = default;

 protected:
  [[nodiscard]] bool IsBlockedDomain(const std::string& domain) const;

 private:
  std::string arena_;
  std::unordered_set<std::string_view> domains_;
};

}  // namespace fptn::filter
