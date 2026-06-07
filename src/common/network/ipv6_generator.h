/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cinttypes>
#include <memory>
#include <mutex>
#include <string>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "common/network/ip_address.h"
#include "common/network/ipv6_utils.h"

namespace fptn::common::network {
class IPv6AddressGenerator {
 public:
  IPv6AddressGenerator(const fptn::common::network::IPv6Address& net_address,
      std::uint32_t subnet_mask) {
    const auto net_address_boost =
        boost::asio::ip::make_address_v6(net_address.ToString());
    net_addr_ = ipv6::toUInt128(net_address_boost);
    max_addr_ =
        net_addr_ |
        ((boost::multiprecision::uint128_t(1) << (128 - subnet_mask)) - 1);
    current_addr_ = net_addr_;
  }

  fptn::common::network::IPv6Address GetNextAddress() noexcept {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    const auto new_ip = current_addr_ + 1;
    if (new_ip < max_addr_) {
      current_addr_ = new_ip;
    } else {
      current_addr_ = net_addr_ + 1;
    }
    return fptn::common::network::IPv6Address(ipv6::toString(current_addr_));
  }

  boost::multiprecision::uint128_t NumAvailableAddresses() const {
    return max_addr_ - net_addr_ - 1;
  }

 private:
  mutable std::mutex mutex_;

  boost::multiprecision::uint128_t net_addr_;
  boost::multiprecision::uint128_t max_addr_;
  boost::multiprecision::uint128_t current_addr_;
};

using IPv6AddressGeneratorSPtr = std::shared_ptr<IPv6AddressGenerator>;
}  // namespace fptn::common::network
