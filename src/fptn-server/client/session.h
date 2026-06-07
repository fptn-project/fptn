/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/
#pragma once

#include <iostream>
#include <memory>
#include <string>

#include "common/client_id.h"
#include "common/network/ip_address.h"

#include "traffic_shaper/leaky_bucket.h"

namespace fptn::client {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

class Session final {
 public:
  struct Config {
    ClientID client_id;
    std::string user_name;
    IPv4Address client_ipv4;
    IPv4Address fake_client_ipv4;
    IPv6Address client_ipv6;
    IPv6Address fake_client_ipv6;
    fptn::traffic_shaper::LeakyBucketSPtr to_client;
    fptn::traffic_shaper::LeakyBucketSPtr from_client;
  };

 public:
  explicit Session(Config config);
  [[nodiscard]] const ClientID& ClientId() const noexcept;

  [[nodiscard]] const std::string& UserName() const noexcept;

  [[nodiscard]] const IPv4Address& ClientIPv4() const noexcept;
  [[nodiscard]] const IPv4Address& FakeClientIPv4() const noexcept;

  [[nodiscard]] const IPv6Address& ClientIPv6() const noexcept;
  [[nodiscard]] const IPv6Address& FakeClientIPv6() const noexcept;

  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperToClient() noexcept;
  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperFromClient() noexcept;

  void DisableChecksumCalculation(const bool value) noexcept;

  fptn::common::network::IPPacketPtr ChangeIPAddressToClientIP(
      fptn::common::network::IPPacketPtr packet) const noexcept;
  fptn::common::network::IPPacketPtr ChangeIPAddressToFakeIP(
      fptn::common::network::IPPacketPtr packet) const noexcept;

 private:
  Config config_;
  bool disable_checksum_calculation_;
};

using SessionSPtr = std::shared_ptr<Session>;

}  // namespace fptn::client
