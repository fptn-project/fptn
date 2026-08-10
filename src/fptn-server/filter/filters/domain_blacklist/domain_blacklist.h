/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "filter/filters/base_filter.h"

namespace fptn::filter {

/**
 * @class DomainBlacklist
 * @brief Blocks blacklisted domains in the server->client direction.
 *
 * On a DNS response for a blacklisted domain (or any of its subdomains) it
 * remembers the real resolved IP addresses and rewrites all A/AAAA answers to
 * loopback (127.0.0.1 / ::1). Any subsequent non-DNS packet arriving from one
 * of those remembered IPs is dropped - a backstop for clients that resolved
 * the domain out of band.
 *
 * @note This filter is applied on the to-client path and shared across the
 * to-client thread pool, so its mutable state is guarded by a mutex.
 */
class DomainBlacklist final : public BaseFilter {
 public:
  explicit DomainBlacklist(const std::vector<std::string>& domains);

  IPPacketPtr apply(IPPacketPtr packet) const override;

  ~DomainBlacklist() override = default;

  [[nodiscard]] std::size_t Size() const noexcept { return domains_.size(); }

 private:
  // Matches the domain and every parent suffix against the blacklist,
  // so a single "vk.com" entry blocks "vk.com" and any "*.vk.com".
  [[nodiscard]] bool IsBlacklisted(const std::string& domain) const;

  std::unordered_set<std::string> domains_;

  mutable std::mutex mutex_;
  mutable std::unordered_set<std::uint32_t> ipv4_addresses_;
  mutable std::unordered_set<std::string> ipv6_addresses_;
};

}  // namespace fptn::filter
