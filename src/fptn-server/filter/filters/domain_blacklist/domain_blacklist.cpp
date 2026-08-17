/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/domain_blacklist/domain_blacklist.h"

#include <algorithm>
#include <cctype>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fptn::filter {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

namespace {
// Strips inline comments and whitespace, lowercases and drops a trailing dot.
std::string Normalize(const std::string& raw) {
  std::string out;
  for (const char c : raw) {
    if (c == '#') {
      break;  // comment
    }
    if (!std::isspace(static_cast<unsigned char>(c))) {
      out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }
  if (!out.empty() && out.back() == '.') {
    out.pop_back();
  }
  return out;
}
}  // namespace

DomainBlacklist::DomainBlacklist(const std::vector<std::string>& domains) {
  for (const auto& raw : domains) {
    const std::string domain = Normalize(raw);
    if (!domain.empty()) {
      domains_.insert(domain);
    }
  }
  SPDLOG_INFO("Domain blacklist loaded: {} domains", domains_.size());
}

bool DomainBlacklist::IsBlacklisted(const std::string& domain) const {
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

void DomainBlacklist::RememberAddresses(
    const std::vector<IPv4Address>& ipv4_addresses,
    const std::vector<IPv6Address>& ipv6_addresses) const {
  {
    const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

    const bool known =
        std::ranges::all_of(ipv4_addresses,
            [this](const auto& address) {
              return ipv4_addresses_.contains(address.ToInt());
            }) &&
        std::ranges::all_of(ipv6_addresses, [this](const auto& address) {
          return ipv6_addresses_.contains(address.ToBytes());
        });
    if (known) {
      return;
    }
  }

  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  for (const auto& address : ipv4_addresses) {
    ipv4_addresses_.insert(address.ToInt());
  }
  for (const auto& address : ipv6_addresses) {
    ipv6_addresses_.insert(address.ToBytes());
  }
}

IPPacketPtr DomainBlacklist::Apply(
    IPPacketPtr packet, Direction direction) const {
  if (direction == Direction::kToClient) {
    if (!packet->IsDns()) {
      return packet;
    }
    auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      std::string domain = std::move(domain_opt).value();
      std::ranges::transform(domain, domain.begin(),
          [](unsigned char c) { return std::tolower(c); });

      if (IsBlacklisted(domain)) {
        // Remember the real resolved IPs before rewriting the answer.
        RememberAddresses(
            packet->GetDnsIPv4Addresses(), packet->GetDnsIPv6Addresses());
        if (packet->RewriteDnsAnswersToLoopback()) {
          SPDLOG_INFO("Domain {} is blacklisted -> loopback", domain);
        }
      }
    }
    return packet;
  }

  if (packet->IsIPv4()) {
    const std::uint32_t dst_ipv4 = packet->GetDstIPv4Address().ToInt();

    const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

    if (ipv4_addresses_.contains(dst_ipv4)) {
      SPDLOG_INFO(
          "Blocked IPv4 packet to {}", packet->GetDstIPv4Address().ToString());
      return nullptr;
    }
  } else if (packet->IsIPv6()) {
    const auto dst_ipv6 = packet->GetDstIPv6Address();

    const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

    if (ipv6_addresses_.contains(dst_ipv6.ToBytes())) {
      SPDLOG_INFO("Blocked IPv6 packet to {}", dst_ipv6.ToString());
      return nullptr;
    }
  }
  return packet;
}

}  // namespace fptn::filter
