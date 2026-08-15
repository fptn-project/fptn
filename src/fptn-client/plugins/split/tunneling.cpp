/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/split/tunneling.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "utils/utils.h"

namespace fptn::plugin {

Tunneling::Tunneling(const std::vector<std::string>& rules,
    routing::RouteManagerSPtr route_manager,
    fptn::routing::RoutingPolicy policy)
    : route_manager_(std::move(route_manager)), policy_(policy) {
  for (const auto& rule : rules) {
    std::string domain = fptn::utils::NormalizeDomainRule(rule);
    if (domain.empty()) {
      SPDLOG_WARN("Wrong pattern {}", rule);
      continue;
    }
    domains_.insert(std::move(domain));
  }
  SPDLOG_INFO("Tunneling rules loaded: {} domains", domains_.size());
}

bool Tunneling::IsMatched(const std::string& domain) const {
  std::string_view suffix(domain);
  while (!suffix.empty()) {
    if (domains_.contains(std::string(suffix))) {
      return true;
    }
    const auto pos = suffix.find('.');
    if (pos == std::string_view::npos) {
      break;
    }
    suffix.remove_prefix(pos + 1);
  }
  return false;
}

std::pair<fptn::common::network::IPPacketPtr, bool> Tunneling::HandlePacket(
    fptn::common::network::IPPacketPtr packet) {
  bool triggered = false;
  if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();
      const bool domain_matched = IsMatched(domain);

      const auto ipv4_addresses = packet->GetDnsIPv4Addresses();
      if (policy_ == routing::RoutingPolicy::kIncludeInVpn) {
        if (!domain_matched) {
          triggered = true;
          route_manager_->AddDnsRoutesIPv4(
              ipv4_addresses, routing::RoutingPolicy::kExcludeFromVpn);
          SPDLOG_INFO(
              "Domain '{}' -> EXCLUDE from VPN (policy: INCLUDE only selected)",
              domain);
        }
      } else if (policy_ == routing::RoutingPolicy::kExcludeFromVpn) {
        if (domain_matched) {
          triggered = true;
          route_manager_->AddDnsRoutesIPv4(
              ipv4_addresses, routing::RoutingPolicy::kExcludeFromVpn);
          SPDLOG_INFO(
              "Domain '{}' -> EXCLUDE from VPN (policy: EXCLUDE selected)",
              domain);
        }
      }
#ifndef __APPLE__
      const auto ipv6_addresses = packet->GetDnsIPv6Addresses();
      if (!ipv6_addresses.empty()) {
        if (policy_ == routing::RoutingPolicy::kIncludeInVpn) {
          if (!domain_matched) {
            triggered = true;
            route_manager_->AddDnsRoutesIPv6(
                ipv6_addresses, routing::RoutingPolicy::kExcludeFromVpn);
            SPDLOG_INFO(
                "Domain '{}' -> EXCLUDE from VPN (policy: INCLUDE only "
                "selected)",
                domain);
          }
        } else if (policy_ == routing::RoutingPolicy::kExcludeFromVpn) {
          if (domain_matched) {
            triggered = true;
            route_manager_->AddDnsRoutesIPv6(
                ipv6_addresses, routing::RoutingPolicy::kExcludeFromVpn);
            SPDLOG_INFO(
                "Domain '{}' -> EXCLUDE from VPN (policy: EXCLUDE selected)",
                domain);
          }
        }
      }
#endif
    }
  }
  return {std::move(packet), triggered};
}

}  // namespace fptn::plugin
