/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "common/client_id.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "nat/client_connection/client_connection.h"
#include "nat/connect_params.h"
#include "traffic_shaper/leaky_bucket.h"

namespace fptn::nat {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

class ConnectionMultiplexer final {
 public:
  static std::shared_ptr<ConnectionMultiplexer> Create(
      const ConnectParams& params,
      IPv4Address fake_client_ipv4,
      IPv6Address fake_client_ipv6,
      fptn::traffic_shaper::LeakyBucketSPtr to_client,
      fptn::traffic_shaper::LeakyBucketSPtr from_client) {
    return std::make_shared<ConnectionMultiplexer>(params,
        std::move(fake_client_ipv4), std::move(fake_client_ipv6),
        std::move(to_client), std::move(from_client));
  }

  ConnectionMultiplexer(const ConnectParams& params,
      IPv4Address fake_client_ipv4,
      IPv6Address fake_client_ipv6,
      fptn::traffic_shaper::LeakyBucketSPtr to_client,
      fptn::traffic_shaper::LeakyBucketSPtr from_client);

  bool AddClientConnection(const ConnectParams& params);
  bool HasClientId(fptn::ClientID client_id) const;
  bool DelConnectionByClientId(fptn::ClientID client_id);
  [[nodiscard]] bool Empty() const;

  // Re-sorts every connection into the sending_/receiving_ buckets by its
  // current role (a connection may be sending, receiving, or both). Connections
  // past their ttl are removed and their client ids returned so the caller can
  // close their transports. Meant to be called periodically by the vpn manager.
  std::vector<fptn::ClientID> UpdateConnectionsStatus();

  std::optional<fptn::ClientID> NextReceiverClientId();

  fptn::common::network::IPPacketPtr ChangeIPAddressToClientIP(
      fptn::common::network::IPPacketPtr packet,
      fptn::ClientID client_id) const noexcept;

  fptn::common::network::IPPacketPtr ChangeIPAddressToFakeIP(
      fptn::common::network::IPPacketPtr packet) const noexcept;

  void DisableChecksumCalculation(bool value) noexcept;

  [[nodiscard]] const std::string& UserName() const noexcept;
  [[nodiscard]] const std::string& SessionId() const noexcept;
  [[nodiscard]] const IPv4Address& FakeClientIPv4() const noexcept;
  [[nodiscard]] const IPv6Address& FakeClientIPv6() const noexcept;

  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperToClient() noexcept;
  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperFromClient() noexcept;

 private:
  mutable std::shared_mutex mutex_;

  const std::string username_;
  const std::string session_id_;

  const IPv4Address fake_client_ipv4_;
  const IPv6Address fake_client_ipv6_;

  fptn::traffic_shaper::LeakyBucketSPtr shaper_to_client_;
  fptn::traffic_shaper::LeakyBucketSPtr shaper_from_client_;

  bool disable_checksum_calculation_;

  std::vector<ClientConnectionPtr> sending_;
  std::vector<ClientConnectionPtr> receiving_;
  mutable std::atomic<std::size_t> round_robin_cursor_{0};
};

using ConnectionMultiplexerSPtr = std::shared_ptr<ConnectionMultiplexer>;

}  // namespace fptn::nat
