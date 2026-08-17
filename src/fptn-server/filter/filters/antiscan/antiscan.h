/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filter/filters/base_filter.h>

#include <boost/multiprecision/cpp_int.hpp>

#include "common/network/ip_address.h"

namespace fptn::filter {

/**
 * @class AntiScanFilter
 * @brief A filter class that blocks packets from IP addresses belonging to a
 * specific network.
 *
 * This class is used to block IP packets that match a given network address and
 * subnet mask. It compares the destination IP address of the packet against the
 * specified network and mask. If the packet belongs to the network, it is
 * blocked.
 *
 * @note This filter does not modify the packets that are not blocked. It simply
 * returns `nullptr` for blocked packets.
 */
class AntiScan : public BaseFilter {
 public:
  AntiScan(
      /* IPv4 */
      const fptn::common::network::IPv4Address& server_ipv4,
      const fptn::common::network::IPv4Address& server_ipv4_net,
      const int server_ip_v4_mask,
      /* IPv6 */
      const fptn::common::network::IPv6Address& server_ipv6,
      const fptn::common::network::IPv6Address& server_ipv6_net,
      const int server_ip_v6_mask);

  IPPacketPtr Apply(IPPacketPtr packet, Direction direction) const override;

  ~AntiScan() override = default;

 private:
  /* IPv4 */
  const std::uint32_t server_ipv4_;
  const std::uint32_t server_ipv4_net_;
  const int server_ipv4_mask_;

  /* IPv6 */
  const boost::multiprecision::uint128_t server_ipv6_;
  const boost::multiprecision::uint128_t server_ipv6_net_;
  const boost::multiprecision::uint128_t server_ipv6_mask_;
};
}  // namespace fptn::filter
