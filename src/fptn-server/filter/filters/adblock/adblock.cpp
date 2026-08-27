/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/adblock/adblock.h"

#include <cctype>
#include <filesystem>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

#include "filter/domain_list/domain_list.h"

namespace fptn::filter {

using fptn::common::network::GetTlsSNI;
using fptn::common::network::IsTlsClientHello;

namespace {

std::string Normalize(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  for (const char c : raw) {
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

AdBlock::AdBlock(
    const std::filesystem::path& data_dir, const std::vector<std::string>& urls)
    : AdBlock(domain_list::Load(data_dir / "ads", urls)) {}

AdBlock::AdBlock(const std::vector<std::string>& domains) {
  const std::size_t total = std::accumulate(domains.begin(), domains.end(),
      std::size_t{0}, [](const std::size_t sum, const std::string& raw) {
        return sum + raw.size();
      });
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
  SPDLOG_INFO("Ads filter loaded: {} domains", domains_.size());
}

bool AdBlock::IsBlockedDomain(const std::string& domain) const {
  std::string_view suffix(domain);
  while (!suffix.empty()) {
    if (domains_.contains(suffix)) {
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

IPPacketPtr AdBlock::Apply(IPPacketPtr packet, Direction direction) const {
  if (direction != Direction::kFromClient || !packet->IsTCP()) {
    return packet;
  }

  const auto [payload, size] = packet->GetTcpPayload();

  // pass all packet except TLS-handshake
  if (!IsTlsClientHello(payload, size)) {
    return packet;
  }
  const auto sni_opt = GetTlsSNI(payload, size);
  if (!sni_opt.has_value()) {
    return packet;
  }
  const std::string& sni = sni_opt.value();
  if (!IsBlockedDomain(sni)) {
    return packet;
  }
  SPDLOG_INFO("Blocked ads tls {}", sni);

  return nullptr;
}

}  // namespace fptn::filter
