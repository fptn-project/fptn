/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "filter/filters/base_filter.h"

namespace fptn::filter {

/**
 * @class DomainBlacklist
 * @brief Blocks blacklisted domains by their TLS SNI and by the IPs they are
 * seen on, learned from DNS answers and from blocked handshakes.
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
  [[nodiscard]] std::string_view GetBlacklistedDomain(
      const std::string& domain) const;

  void RememberIPv4Address(const fptn::common::network::IPv4Address& address,
      std::string_view domain) const;

  void RememberIPv6Address(const fptn::common::network::IPv6Address& address,
      std::string_view domain) const;

  [[nodiscard]] std::string_view GetBlockedIPv4Domain(
      const fptn::common::network::IPv4Address& address) const;

  [[nodiscard]] std::string_view GetBlockedIPv6Domain(
      const fptn::common::network::IPv6Address& address) const;

 private:
  using IPv6Bytes = fptn::common::network::IPv6Address::Bytes;

  struct IPv6BytesHash {
    std::size_t operator()(const IPv6Bytes& bytes) const noexcept {
      return std::hash<std::string_view>{}(std::string_view(
          reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    }
  };

  struct Entry {
    std::string_view domain;
    std::chrono::steady_clock::time_point expires_at;
  };

 private:
  std::unordered_set<std::string> domains_;

  mutable std::shared_mutex mutex_;
  mutable std::unordered_map<std::uint32_t, Entry> ipv4_addresses_;
  mutable std::unordered_map<IPv6Bytes, Entry, IPv6BytesHash> ipv6_addresses_;
};

}  // namespace fptn::filter
