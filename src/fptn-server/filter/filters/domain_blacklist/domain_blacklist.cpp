/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/domain_blacklist/domain_blacklist.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace fptn::filter {

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

IPPacketPtr DomainBlacklist::apply(IPPacketPtr packet) const {
  if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      std::string domain = domain_opt.value();
      std::transform(domain.begin(), domain.end(), domain.begin(),
          [](unsigned char c) { return std::tolower(c); });

      if (IsBlacklisted(domain)) {
        // Remember the real resolved IPs before rewriting the answer.
        const auto ipv4_addresses = packet->GetDnsIPv4Addresses();
        const auto ipv6_addresses = packet->GetDnsIPv6Addresses();
        {
          const std::unique_lock<std::mutex> lock(mutex_);
          for (const auto& ipv4_address : ipv4_addresses) {
            ipv4_addresses_.insert(ipv4_address.ToInt());
          }
          for (const auto& ipv6_address : ipv6_addresses) {
            ipv6_addresses_.insert(ipv6_address.ToString());
          }
        }
        if (packet->RewriteDnsAnswersToLoopback()) {
          SPDLOG_INFO("Domain {} is blacklisted -> loopback", domain);
        }
      }
    }
    return packet;
  }

  // Non-DNS: drop packets coming from a blacklisted IP.
  if (packet->IsIPv4()) {
    const std::uint32_t src_ipv4 = packet->GetSrcIPv4Address().ToInt();
    const std::unique_lock<std::mutex> lock(mutex_);
    if (ipv4_addresses_.contains(src_ipv4)) {
      SPDLOG_INFO("Blocked IPv4 packet from {}",
          packet->GetSrcIPv4Address().ToString());
      return nullptr;
    }
  } else if (packet->IsIPv6()) {
    const std::string src_ipv6 = packet->GetSrcIPv6Address().ToString();
    const std::unique_lock<std::mutex> lock(mutex_);
    if (ipv6_addresses_.contains(src_ipv6)) {
      SPDLOG_INFO("Blocked IPv6 packet from {}", src_ipv6);
      return nullptr;
    }
  }
  return packet;
}

}  // namespace fptn::filter
