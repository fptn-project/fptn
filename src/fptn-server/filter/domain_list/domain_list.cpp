/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/domain_list/domain_list.h"

#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib/httplib.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>    // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace fptn::filter::domain_list {

namespace {

constexpr auto kMaxAge = std::chrono::hours{1};
constexpr int kConnectionTimeoutSec = 10;
constexpr int kReadTimeoutSec = 60;

// Cache file name built from the URL, so a changed URL gets its own file.
std::string CacheFileName(const std::string& url) {
  std::string name;
  for (const char c : url) {
    if (std::isalnum(static_cast<unsigned char>(c)) != 0) {
      name += c;
    } else if (!name.empty() && name.back() != '-') {
      name += '-';
    }
  }
  constexpr std::size_t kMaxNameLength = 100;
  if (name.size() > kMaxNameLength) {
    name.erase(0, name.size() - kMaxNameLength);
  }
  return name + ".txt";
}

bool IsFresh(const std::filesystem::path& file) {
  std::error_code error;
  const auto modified = std::filesystem::last_write_time(file, error);
  if (error) {
    return false;
  }
  return decltype(modified)::clock::now() - modified < kMaxAge;
}

bool Download(const std::string& url, const std::filesystem::path& file) {
  const std::size_t scheme = url.find("://");
  if (scheme == std::string::npos) {
    SPDLOG_ERROR("Domain list url is malformed: {}", url);
    return false;
  }
  const std::size_t path = url.find('/', scheme + 3);
  const std::string host = url.substr(0, path);
  const std::string target =
      (path == std::string::npos) ? "/" : url.substr(path);

  httplib::Client client(host);
  client.set_follow_location(true);
  client.set_connection_timeout(kConnectionTimeoutSec);
  client.set_read_timeout(kReadTimeoutSec);

  const auto response = client.Get(target);
  if (!response) {
    SPDLOG_ERROR("Domain list download failed: {} ({})", url,
        httplib::to_string(response.error()));
    return false;
  }
  if (response->status != 200) {
    SPDLOG_ERROR(
        "Domain list download failed: {} (status {})", url, response->status);
    return false;
  }
  if (response->body.empty()) {
    SPDLOG_ERROR("Domain list is empty: {}", url);
    return false;
  }

  const std::filesystem::path temporary =
      std::filesystem::path(file).concat(".tmp");
  {
    std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
    if (!out) {
      SPDLOG_ERROR("Domain list cannot be written: {}", temporary.string());
      return false;
    }
    out << response->body;
    if (!out) {
      SPDLOG_ERROR("Domain list cannot be written: {}", temporary.string());
      return false;
    }
  }

  std::error_code error;
  std::filesystem::rename(temporary, file, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    SPDLOG_ERROR("Domain list cannot be saved: {}", file.string());
    return false;
  }
  SPDLOG_INFO("Domain list downloaded: {} -> {} ({} bytes)", url, file.string(),
      response->body.size());
  return true;
}

// Accepts both the hosts format ('0.0.0.0 domain') and a bare domain per line.
std::string ParseLine(std::string line) {
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }
  if (line.empty() || line[0] == '#' || line[0] == '!') {
    return {};
  }
  const std::size_t comment = line.find('#');
  if (comment != std::string::npos) {
    line.erase(comment);
  }
  line = fptn::common::utils::ToLowerCase(fptn::common::utils::Trim(line));
  if (line.empty()) {
    return {};
  }

  const std::size_t separator = line.find_first_of(" \t");
  std::string domain =
      (separator == std::string::npos) ? line : line.substr(separator + 1);
  domain = fptn::common::utils::Trim(domain);
  const std::size_t dot = domain.find('.');
  if (dot == std::string::npos || domain == "0.0.0.0") {
    return {};
  }
  if (domain.ends_with(".local") || domain.ends_with(".localdomain") ||
      domain.ends_with(".localhost")) {
    return {};
  }
  return domain;
}

void ReadFile(
    const std::filesystem::path& file, std::vector<std::string>& domains) {
  std::ifstream in(file);
  if (!in) {
    SPDLOG_WARN("Domain list cannot be read: {}", file.string());
    return;
  }
  std::size_t count = 0;
  std::string line;
  while (std::getline(in, line)) {
    std::string domain = ParseLine(std::move(line));
    if (!domain.empty()) {
      domains.push_back(std::move(domain));
      count += 1;
    }
  }
  SPDLOG_INFO("Domain list loaded: {} ({} domains)", file.string(), count);
}

}  // namespace

std::vector<std::string> Load(const std::filesystem::path& cache_dir,
    const std::vector<std::string>& urls) {
  std::vector<std::string> domains;

  std::error_code error;
  std::filesystem::create_directories(cache_dir, error);
  if (error) {
    SPDLOG_ERROR("Domain list directory cannot be created: {} ({})",
        cache_dir.string(), error.message());
    return domains;
  }

  for (const auto& url : urls) {
    if (url.empty()) {
      continue;
    }
    const std::filesystem::path file = cache_dir / CacheFileName(url);
    if (!IsFresh(file)) {
      Download(url, file);
    }
    if (std::filesystem::exists(file)) {
      ReadFile(file, domains);
    }
  }
  return domains;
}

}  // namespace fptn::filter::domain_list
