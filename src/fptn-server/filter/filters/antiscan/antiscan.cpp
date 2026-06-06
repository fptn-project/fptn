/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/antiscan/antiscan.h"

#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h>
#elif _WIN32
#pragma warning(disable : 4996)
#include <Winsock2.h>
#pragma warning(default : 4996)
#endif

#include <common/network/ipv6_utils.h>

namespace fptn::filter {

AntiScan::AntiScan(
    /* IPv4 */
    const fptn::common::network::IPv4Address& server_ipv4,
    const fptn::common::network::IPv4Address& server_ipv4_net,
    const int server_ip_v4_mask,
    /* IPv6 */
    const fptn::common::network::IPv6Address& server_ipv6,
    const fptn::common::network::IPv6Address& server_ipv6_net,
    const int server_ip_v6_mask)
    : server_ipv4_(server_ipv4.ToInt()),
      server_ipv4_net_(server_ipv4_net.ToInt()),
      server_ipv4_mask_((0xFFFFFFFF << (32 - server_ip_v4_mask))),
      server_ipv6_(fptn::common::network::ipv6::toUInt128(server_ipv6)),
      server_ipv6_net_(fptn::common::network::ipv6::toUInt128(server_ipv6_net)),
      server_ipv6_mask_(
          (boost::multiprecision::uint128_t(1) << (128 - server_ip_v6_mask)) -
          1) {}

IPPacketPtr AntiScan::apply(IPPacketPtr packet) const {
  // Prevent sending requests to the VPN virtual network from the client
  static const std::uint32_t kIpv4BroadcastInt =
      fptn::common::network::IPv4Address("255.255.255.255").ToInt();

  if (packet->IsIPv4()) {
    const std::uint32_t dst = packet->GetDstIPv4Address().ToInt();
    const bool is_in_network =
        (dst & server_ipv4_mask_) == (server_ipv4_net_ & server_ipv4_mask_);
    if (server_ipv4_ == dst || (!is_in_network && kIpv4BroadcastInt != dst)) {
      return packet;
    }
  } else if (packet->IsIPv6()) {
    const auto dst =
        fptn::common::network::ipv6::toUInt128(packet->GetDstIPv6Address());
    const auto max_addr = server_ipv6_net_ | server_ipv6_mask_;
    const bool is_in_network = (server_ipv6_net_ <= dst && dst <= max_addr);
    if (server_ipv6_ == dst || !is_in_network) {
      return packet;
    }
  }
  return nullptr;
}
}  // namespace fptn::filter
