/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/domain_blacklist/domain_blacklist.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/utils/utils.h"

#include "filter/domain_list/domain_list.h"

namespace fptn::filter {

using fptn::common::network::GetTlsSNI;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;
using fptn::common::network::IsTlsClientHello;

namespace {

constexpr std::chrono::hours kAddressTtl{1};

std::string Normalize(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  for (const char c : raw) {
    if (c == '#') {
      break;
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

std::vector<std::string> Collect(const std::filesystem::path& data_dir,
    const std::vector<std::string>& urls,
    const std::filesystem::path& file) {
  std::vector<std::string> domains = fptn::common::utils::SplitCommaSeparated(
      FPTN_SERVER_DEFAULT_BLACKLIST_DOMAINS);

  const std::vector<std::string> downloaded =
      domain_list::Load(data_dir / "blacklist", urls);
  domains.insert(domains.end(), downloaded.begin(), downloaded.end());

  if (file.empty()) {
    return domains;
  }
  if (!std::filesystem::exists(file)) {
    SPDLOG_WARN("Domain blacklist file not found: {}", file.string());
    return domains;
  }
  std::ifstream in(file);
  std::string line;
  while (std::getline(in, line)) {
    domains.push_back(std::move(line));
  }
  SPDLOG_INFO("Domain blacklist file loaded: {}", file.string());
  return domains;
}
}  // namespace

DomainBlacklist::DomainBlacklist(const std::filesystem::path& data_dir,
    const std::vector<std::string>& urls,
    const std::filesystem::path& file)
    : DomainBlacklist(Collect(data_dir, urls, file)) {}

DomainBlacklist::DomainBlacklist(const std::vector<std::string>& domains) {
  const std::size_t total = std::accumulate(domains.begin(), domains.end(),
      std::size_t{0},
      [](std::size_t sum, const std::string& raw) { return sum + raw.size(); });
  arena_.reserve(total);
  domains_.reserve(domains.size());

  for (const auto& raw : domains) {
    const std::string domain = Normalize(raw);
    if (domain.empty()) {
      continue;
    }
    const std::size_t offset = arena_.size();
    arena_.append(domain);
    if (!domains_.emplace(arena_.data() + offset, domain.size()).second) {
      arena_.resize(offset);
    }
  }
  SPDLOG_INFO("Domain blacklist loaded: {} domains", domains_.size());
}

std::string_view DomainBlacklist::GetBlacklistedDomain(
    const std::string& domain) const {
  std::string_view suffix(domain);
  while (!suffix.empty()) {
    const auto it = domains_.find(suffix);
    if (it != domains_.end()) {
      return *it;
    }
    const auto pos = suffix.find('.');
    if (pos == std::string_view::npos) {
      break;
    }
    suffix.remove_prefix(pos + 1);
  }
  return {};
}

void DomainBlacklist::RememberIPv4Address(
    const IPv4Address& address, std::string_view domain) const {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto now = std::chrono::steady_clock::now();
  if (ipv4_addresses_.size() >= ipv4_prune_size_) {
    std::erase_if(ipv4_addresses_, [now](const auto& entry) {
      return entry.second.expires_at.load(std::memory_order_relaxed) <= now;
    });
    ipv4_prune_size_ = (ipv4_addresses_.size() * 2) + 1;
  }
  const auto [it, inserted] =
      ipv4_addresses_.try_emplace(address.ToInt(), domain, now + kAddressTtl);
  if (!inserted) {
    it->second.domain = domain;
    it->second.expires_at.store(now + kAddressTtl, std::memory_order_relaxed);
  }
}

void DomainBlacklist::RememberIPv6Address(
    const IPv6Address& address, std::string_view domain) const {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto now = std::chrono::steady_clock::now();
  if (ipv6_addresses_.size() >= ipv6_prune_size_) {
    std::erase_if(ipv6_addresses_, [now](const auto& entry) {
      return entry.second.expires_at.load(std::memory_order_relaxed) <= now;
    });
    ipv6_prune_size_ = (ipv6_addresses_.size() * 2) + 1;
  }
  const auto [it, inserted] =
      ipv6_addresses_.try_emplace(address.ToBytes(), domain, now + kAddressTtl);
  if (!inserted) {
    it->second.domain = domain;
    it->second.expires_at.store(now + kAddressTtl, std::memory_order_relaxed);
  }
}

std::string_view DomainBlacklist::GetBlockedIPv4Domain(
    const IPv4Address& address) const {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = ipv4_addresses_.find(address.ToInt());
  if (it == ipv4_addresses_.end()) {
    return {};
  }
  const auto now = std::chrono::steady_clock::now();
  if (it->second.expires_at.load(std::memory_order_relaxed) <= now) {
    return {};
  }
  it->second.expires_at.store(now + kAddressTtl, std::memory_order_relaxed);
  return it->second.domain;
}

std::string_view DomainBlacklist::GetBlockedIPv6Domain(
    const IPv6Address& address) const {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = ipv6_addresses_.find(address.ToBytes());
  if (it == ipv6_addresses_.end()) {
    return {};
  }
  const auto now = std::chrono::steady_clock::now();
  if (it->second.expires_at.load(std::memory_order_relaxed) <= now) {
    return {};
  }
  it->second.expires_at.store(now + kAddressTtl, std::memory_order_relaxed);
  return it->second.domain;
}

IPPacketPtr DomainBlacklist::Apply(
    IPPacketPtr packet, Direction direction) const {
  // DNS: remember resolved addresses
  if (direction == Direction::kToClient) {
    if (!packet->IsDns()) {
      return packet;
    }
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();
      const std::string_view blacklisted = GetBlacklistedDomain(domain);

      if (!blacklisted.empty()) {
        for (const auto& address : packet->GetDnsIPv4Addresses()) {
          RememberIPv4Address(address, blacklisted);
          SPDLOG_INFO("Blacklisted dns {} {}", address.ToString(), domain);
        }
        for (const auto& address : packet->GetDnsIPv6Addresses()) {
          RememberIPv6Address(address, blacklisted);
          SPDLOG_INFO("Blacklisted dns {} {}", address.ToString(), domain);
        }
      }
    }
    return packet;
  }

  // TLS: block by SNI
  if (packet->IsTCP()) {
    const auto [payload, size] = packet->GetTcpPayload();
    // pass all packet except TLS-handshake
    if (!IsTlsClientHello(payload, size)) {
      return packet;
    }
    const auto sni_opt = GetTlsSNI(payload, size);
    if (sni_opt.has_value()) {
      const std::string& sni = sni_opt.value();
      const std::string_view blacklisted = GetBlacklistedDomain(sni);

      if (blacklisted.empty()) {
        return packet;
      }
      if (packet->IsIPv4()) {
        const IPv4Address dst_ipv4 = packet->GetDstIPv4Address();
        RememberIPv4Address(dst_ipv4, blacklisted);
        SPDLOG_INFO("Blocked tls {} {}", dst_ipv4.ToString(), sni);
      } else if (packet->IsIPv6()) {
        const IPv6Address dst_ipv6 = packet->GetDstIPv6Address();
        RememberIPv6Address(dst_ipv6, blacklisted);
        SPDLOG_INFO("Blocked tls {} {}", dst_ipv6.ToString(), sni);
      }
      return nullptr;
    }
    return packet;
  }

  if (!packet->IsQuicInitial() && !packet->IsICMPv4() && !packet->IsICMPv6()) {
    return packet;
  }

  // ICMP and QUIC: block by address
  if (packet->IsIPv4()) {
    const IPv4Address dst_ipv4 = packet->GetDstIPv4Address();
    const std::string_view domain = GetBlockedIPv4Domain(dst_ipv4);

    if (!domain.empty()) {
      if (packet->IsQuicInitial()) {
        SPDLOG_INFO("Blocked quic {} {}", dst_ipv4.ToString(), domain);
        return nullptr;
      }
      if (packet->IsICMPv4()) {
        SPDLOG_INFO("Blocked icmp {} {}", dst_ipv4.ToString(), domain);
        return nullptr;
      }
    }
  } else if (packet->IsIPv6()) {
    const IPv6Address dst_ipv6 = packet->GetDstIPv6Address();
    const std::string_view domain = GetBlockedIPv6Domain(dst_ipv6);

    if (!domain.empty()) {
      if (packet->IsQuicInitial()) {
        SPDLOG_INFO("Blocked quic {} {}", dst_ipv6.ToString(), domain);
        return nullptr;
      }
      if (packet->IsICMPv6()) {
        SPDLOG_INFO("Blocked icmp {} {}", dst_ipv6.ToString(), domain);
        return nullptr;
      }
    }
  }
  return packet;
}

}  // namespace fptn::filter
