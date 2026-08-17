/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <unordered_set>

#include <re2/re2.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace fptn::utils {

inline std::string NormalizeDomainRule(const std::string& rule) {
  const std::string domain_prefix = "domain:";
  std::string domain = fptn::common::utils::Trim(rule);

  std::ranges::transform(domain, domain.begin(), [](const char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  });

  if (domain.starts_with(domain_prefix)) {
    domain = domain.substr(domain_prefix.length());
  }
  if (!domain.empty() && domain.back() == '.') {
    domain.pop_back();
  }
  return domain;
}

// Matches the domain and every parent suffix, so a single "vk.com" rule
// matches "vk.com" and any "*.vk.com".
inline bool IsDomainMatched(
    const std::unordered_set<std::string>& domains, const std::string& domain) {
  std::string_view suffix(domain);
  while (!suffix.empty()) {
    if (domains.contains(std::string(suffix))) {
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

inline std::string DomainToRegex(const std::string& pattern) {
  const std::string domain = NormalizeDomainRule(pattern);
  if (domain.empty()) {
    return {};
  }

  std::string escaped;
  escaped.reserve(domain.length() * 2);
  for (const char c : domain) {
    if (c == '.') {
      escaped += "\\.";
    } else {
      escaped += c;
    }
  }
  // return R"(\.)" + escaped + R"($)";
  // return R"((?:^|\.))" + escaped + R"((?:\.|$)?)";
  return R"((?:^|\.))" + escaped + R"($)";
}
}  // namespace fptn::utils
