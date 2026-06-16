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

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

class RouteManager final {
 public:
  struct Config {
    std::string out_interface_name;

    IPv4Address tun_interface_address_ipv4;
    IPv6Address tun_interface_address_ipv6;

    IPv4Address vpn_server_ip;

    IPv4Address dns_server_ipv4;
    IPv6Address dns_server_ipv6;

    IPv4Address gateway_ipv4;
    IPv6Address gateway_ipv6;

    std::vector<std::string> exclude_networks;
    std::vector<std::string> include_networks;
#if _WIN32
    bool enable_advanced_dns_management;
#endif
  };

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
  explicit RouteManager(Config config);
  ~RouteManager();

  bool Apply(std::string tun_name);
  bool Clean();

  bool AddDnsRoutesIPv4(
      const std::vector<fptn::common::network::IPv4Address>& ips,
      RoutingPolicy policy);

  bool AddDnsRoutesIPv6(
      const std::vector<fptn::common::network::IPv6Address>& ips,
      RoutingPolicy policy);

 protected:
  bool AddExcludeNetworks(const std::vector<std::string>& networks);
  bool AddIncludeNetworks(const std::vector<std::string>& networks);

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const Config config_;

  std::string tun_interface_name_;

  std::unordered_set<RouteEntry, RouteEntry::Hash> dns_routes_ipv4_;
  std::unordered_set<RouteEntry, RouteEntry::Hash> dns_routes_ipv6_;

  std::unordered_set<RouteEntry, RouteEntry::Hash> additional_routes_ipv4_;
  std::unordered_set<RouteEntry, RouteEntry::Hash> additional_routes_ipv6_;

 private:
  std::string detected_out_interface_name_;
  fptn::common::network::IPv4Address detected_gateway_ipv4_;
  fptn::common::network::IPv6Address detected_gateway_ipv6_;

#ifdef __linux__
  std::vector<std::string> original_dns_servers_;
#endif
};

using RouteManagerSPtr = std::shared_ptr<RouteManager>;
}  // namespace fptn::routing
