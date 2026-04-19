/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "common/network/ip_address.h"

namespace fptn::routing {
std::string GetDefaultNetworkInterfaceName();
fptn::common::network::IPv4Address GetDefaultGatewayIPAddress();
fptn::common::network::IPv4Address ResolveDomain(const std::string& domain);

fptn::common::network::IPv6Address GetDefaultGatewayIPv6Address();

enum class RoutingPolicy {
  kExcludeFromVpn,  // Traffic bypasses VPN
  kIncludeInVpn     // Traffic goes through VPN
};

class RouteManager final {
 protected:
  struct RouteEntry {
    std::string destination;
    RoutingPolicy policy;

    bool operator==(const RouteEntry& other) const {
      return destination == other.destination && policy == other.policy;
    }

    struct Hash {
      std::size_t operator()(const RouteEntry& entry) const {
        return std::hash<std::string>{}(entry.destination) ^
               (std::hash<int>{}(static_cast<int>(entry.policy)) << 1);
      }
    };
  };

 public:
  RouteManager(std::string out_interface_name,
      std::string tun_interface_name,
      fptn::common::network::IPv4Address vpn_server_ip,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      fptn::common::network::IPv4Address gateway_ipv4,
      fptn::common::network::IPv6Address gateway_ipv6,
      fptn::common::network::IPv4Address tun_interface_address_ipv4,
      fptn::common::network::IPv6Address tun_interface_address_ipv6
#if _WIN32
      ,
      bool enable_advanced_dns_management_
#endif
  );  // NOLINT
  ~RouteManager();

  void UpdateTunInterfaceName(const std::string& name) {
    tun_interface_name_ = name;
  }

  bool Apply();
  bool Clean();

  bool AddDnsRoutesIPv4(
      const std::vector<fptn::common::network::IPv4Address>& ips,
      RoutingPolicy policy);

  bool AddDnsRoutesIPv6(
      const std::vector<fptn::common::network::IPv6Address>& ips,
      RoutingPolicy policy);

  bool AddExcludeNetworks(const std::vector<std::string>& networks);
  bool AddIncludeNetworks(const std::vector<std::string>& networks);

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const std::string out_interface_name_;
  std::string tun_interface_name_;
  const fptn::common::network::IPv4Address vpn_server_ip_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;
  const fptn::common::network::IPv4Address gateway_ipv4_;
  const fptn::common::network::IPv6Address gateway_ipv6_;
  const fptn::common::network::IPv4Address tun_interface_address_ipv4_;
  const fptn::common::network::IPv6Address tun_interface_address_ipv6_;

#if _WIN32
  const bool enable_advanced_dns_management_;
#endif

  std::unordered_set<RouteEntry, RouteEntry::Hash> dns_routes_ipv4_;
  std::unordered_set<RouteEntry, RouteEntry::Hash> dns_routes_ipv6_;

  std::unordered_set<RouteEntry, RouteEntry::Hash> additional_routes_ipv4_;
  std::unordered_set<RouteEntry, RouteEntry::Hash> additional_routes_ipv6_;

 private:
  std::string detected_out_interface_name_;
  fptn::common::network::IPv4Address detected_gateway_ipv4_;

#ifdef __linux__
  std::vector<std::string> original_dns_servers_;
#endif
};

using RouteManagerSPtr = std::shared_ptr<RouteManager>;
}  // namespace fptn::routing
