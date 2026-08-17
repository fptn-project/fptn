/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <functional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "filter/filters/base_filter.h"

namespace fptn::filter {

/**
 * @class DomainBlacklist
 * @brief Blocks blacklisted domains by the IPs they resolve to.
 *
 * To the client: on a DNS response for a blacklisted domain (or any of its
 * subdomains) it remembers the real resolved IP addresses and rewrites all
 * A/AAAA answers to loopback (127.0.0.1 / ::1).
 *
 * From the client: drops packets addressed to one of those remembered IPs -
 * a backstop for clients that resolved the domain out of band.
 *
 * @note This filter is applied on both paths and shared across their thread
 * pools, so its mutable state is guarded by a read-write mutex.
 */
class DomainBlacklist final : public BaseFilter {
 public:
  explicit DomainBlacklist(const std::vector<std::string>& domains);

  IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const override;

  ~DomainBlacklist() override = default;

  [[nodiscard]] std::size_t Size() const noexcept { return domains_.size(); }

 protected:
  [[nodiscard]] bool IsBlacklisted(const std::string& domain) const;

  void RememberAddresses(
      const std::vector<fptn::common::network::IPv4Address>& ipv4_addresses,
      const std::vector<fptn::common::network::IPv6Address>& ipv6_addresses)
      const;

 private:
  using IPv6Bytes = fptn::common::network::IPv6Address::Bytes;

  struct IPv6BytesHash {
    std::size_t operator()(const IPv6Bytes& bytes) const noexcept {
      return std::hash<std::string_view>{}(std::string_view(
          reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    }
  };

  std::unordered_set<std::string> domains_;

  mutable std::shared_mutex mutex_;
  mutable std::unordered_set<std::uint32_t> ipv4_addresses_;
  mutable std::unordered_set<IPv6Bytes, IPv6BytesHash> ipv6_addresses_;
};

}  // namespace fptn::filter
