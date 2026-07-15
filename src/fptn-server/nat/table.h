/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/network/ip_address.h"
#include "common/network/ipv4_generator.h"
#include "common/network/ipv6_generator.h"

#include "client/session.h"
#include "statistic/metrics.h"
#include "traffic_shaper/leaky_bucket.h"

namespace fptn::nat {

class Table final {
  using IPv4INT = std::uint32_t;

 public:
  struct Config {
    fptn::common::network::IPv4Address tun_ipv4;
    fptn::common::network::IPv4Address tun_ipv4_network;
    std::uint32_t tun_network_ipv4_mask;
    fptn::common::network::IPv6Address tun_ipv6;
    fptn::common::network::IPv6Address tun_ipv6_network;
    std::uint32_t tun_network_ipv6_mask;
  };

 public:
  explicit Table(Config config);

  // deprecated
  fptn::client::SessionSPtr CreateClientSession(ClientID client_id,
      const std::string& user_name,
      const fptn::common::network::IPv4Address& client_ipv4,
      const fptn::common::network::IPv6Address& client_ipv6,
      const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
      const fptn::traffic_shaper::LeakyBucketSPtr& from_client);

  fptn::client::SessionSPtr CreateClientSession2(ClientID client_id,
      const std::string& user_name,
      const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
      const fptn::traffic_shaper::LeakyBucketSPtr& from_client);

  bool DelClientSession(ClientID client_id);
  void UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus);

 public:
  fptn::client::SessionSPtr GetSessionByFakeIPv4(
      const fptn::common::network::IPv4Address& ip) noexcept;
  fptn::client::SessionSPtr GetSessionByFakeIPv6(
      const fptn::common::network::IPv6Address& ip) noexcept;
  fptn::client::SessionSPtr GetSessionByClientId(ClientID clientId) noexcept;

  std::size_t GetNumberActiveSessionByUsername(const std::string& username);

 private:
  mutable std::shared_mutex mutex_;

  Config config_;

  fptn::common::network::IPv4AddressGenerator ipv4_generator_;
  fptn::common::network::IPv6AddressGenerator ipv6_generator_;

  std::vector<fptn::common::network::IPv4Address> free_ipv4_;
  std::vector<fptn::common::network::IPv6Address> free_ipv6_;

  std::unordered_map<IPv4INT, fptn::client::SessionSPtr>
      ipv4_to_sessions_;  // ipv4
  std::unordered_map<std::string, fptn::client::SessionSPtr>
      ipv6_to_sessions_;  // ipv6
  std::unordered_map<ClientID, fptn::client::SessionSPtr>
      client_id_to_sessions_;
};

typedef std::shared_ptr<Table> TableSPtr;

}  // namespace fptn::nat
