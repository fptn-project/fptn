/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_set>

#include "common/network/ip_packet.h"

namespace fptn::adblock {

class AdBlocker final {
 public:
  AdBlocker();
  explicit AdBlocker(std::unordered_set<std::string> blocked_domains);

  fptn::common::network::IPPacketPtr ProcessOutgoingDns(
      const fptn::common::network::IPPacket& packet) const;

  std::size_t Size() const noexcept { return blocked_domains_.size(); }

 private:
  bool IsBlocked(const std::string& domain) const;

  std::unordered_set<std::string> blocked_domains_;
};

using AdBlockerPtr = std::shared_ptr<AdBlocker>;

}  // namespace fptn::adblock
