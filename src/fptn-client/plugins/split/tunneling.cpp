/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/split/tunneling.h"

#include <algorithm>
#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "utils/utils.h"

namespace fptn::plugin {

Tunneling::Tunneling(const std::vector<std::string>& rules,
    routing::RouteManagerSPtr route_manager,
    fptn::routing::RoutingPolicy policy)
    : route_manager_(std::move(route_manager)), policy_(policy) {
  RE2::Options re_options;
  re_options.set_case_sensitive(false);
  re_options.set_log_errors(false);

  for (const auto& rule : rules) {
    const std::string regex_pattern = fptn::utils::DomainToRegex(rule);
    if (!regex_pattern.empty()) {
      auto re = std::make_unique<RE2>(regex_pattern, re_options);
      if (re->ok()) {
        SPDLOG_INFO("Added tunneling rule: '{}' -> '{}'", rule, regex_pattern);
        rules_.push_back(std::move(re));
      } else {
        SPDLOG_WARN("Invalid regex pattern: {}, item={}", re->error(), rule);
      }
    } else {
      SPDLOG_WARN("Wrong pattern {}", rule);
    }
  }
}

std::pair<fptn::common::network::IPPacketPtr, bool> Tunneling::HandlePacket(
    fptn::common::network::IPPacketPtr packet) {
  bool triggered = false;
  if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();
      const bool domain_matched = std::ranges::any_of(rules_,
          [&domain](const auto& re) { return RE2::PartialMatch(domain, *re); });

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
