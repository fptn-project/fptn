/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/network/ip_address.h"
#include "common/network/ipv4_generator.h"
#include "common/network/ipv6_generator.h"

#include "nat/connect_params.h"
#include "nat/connection_multiplexer/connection_multiplexer.h"
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

  // Registers a physical connection. Connections sharing params.request
  // .session_id are grouped into the same multiplexer (one fake IP pair). The
  // shapers are used only when a brand new multiplexer is created. Returns the
  // multiplexer the connection belongs to, or nullptr on failure.
  ConnectionMultiplexerSPtr AddConnection(const ConnectParams& params,
      const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
      const fptn::traffic_shaper::LeakyBucketSPtr& from_client);

  bool DelConnectionByClientId(ClientID client_id);
  void UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus);

  // Re-sorts the connections of every session by their current role and returns
  // the client ids that outlived their ttl (their transports must be closed).
  // Called periodically by the vpn manager.
  std::vector<ClientID> UpdateConnectionsStatus();

 public:
  ConnectionMultiplexerSPtr GetMultiplexerByFakeIPv4(
      const fptn::common::network::IPv4Address& ip) noexcept;
  ConnectionMultiplexerSPtr GetMultiplexerByFakeIPv6(
      const fptn::common::network::IPv6Address& ip) noexcept;
  ConnectionMultiplexerSPtr GetMultiplexerByClientId(
      ClientID client_id) noexcept;

  std::size_t GetNumberActiveSessionByUsername(const std::string& username);

 private:
  // Must be called with mutex_ held.
  void ReleaseSessionIfEmpty(const ConnectionMultiplexerSPtr& mplx);

 private:
  mutable std::shared_mutex mutex_;

  Config config_;

  fptn::common::network::IPv4AddressGenerator ipv4_generator_;
  fptn::common::network::IPv6AddressGenerator ipv6_generator_;

  std::vector<fptn::common::network::IPv4Address> free_ipv4_;
  std::vector<fptn::common::network::IPv6Address> free_ipv6_;

  std::unordered_map<std::string, ConnectionMultiplexerSPtr> session_to_mplx_;
  std::unordered_map<IPv4INT, ConnectionMultiplexerSPtr> ipv4_to_mplx_;
  std::unordered_map<std::string, ConnectionMultiplexerSPtr> ipv6_to_mplx_;
  std::unordered_map<ClientID, ConnectionMultiplexerSPtr> client_to_mplx_;
};

using TableSPtr = std::shared_ptr<Table>;

}  // namespace fptn::nat
