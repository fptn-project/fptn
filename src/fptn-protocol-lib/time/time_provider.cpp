/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/time/time_provider.h"

#include <string>
#include <utility>

#include <ntp_client.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::time {

TimeProvider::TimeProvider(NtpServers servers)
    : servers_(std::move(servers)), offset_seconds_(0) {
  SyncWithNtp();
}

std::string TimeProvider::Rfc7231Date() const {
  const std::uint32_t timestamp = NowTimestamp();
  const auto now = static_cast<std::time_t>(timestamp);
  char buf[128] = {0};
#ifdef _WIN32
  std::tm tm{};
  if (gmtime_s(&tm, &now) == 0) {
    if (std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
      return std::string(buf);
    }
  }
#else
  std::tm tm{};
  if (gmtime_r(&now, &tm)) {
    if (std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
      return std::string(buf);
    }
  }
#endif
  return {};
}

std::int32_t TimeProvider::OffsetSeconds() const {
  return offset_seconds_.load();
}

std::uint32_t TimeProvider::NowTimestamp() const {
  return static_cast<std::uint32_t>(
      std::time(nullptr) + offset_seconds_.load());
}

bool TimeProvider::SyncWithNtp() {
  const std::scoped_lock lock(mutex_);  // mutex

  return Refresh();
}

bool TimeProvider::Refresh() {
  for (const auto& [server, port] : servers_) {
    try {
      ntp::NTPClient ntp_client(server, port);
      if (const auto epoch_server_ms = ntp_client.request_time()) {
        const auto server_timestamp =
            static_cast<std::uint64_t>(epoch_server_ms / 1000);
        const auto client_timestamp =
            static_cast<std::int64_t>(std::time(nullptr));
        offset_seconds_ =
            static_cast<std::int32_t>(server_timestamp - client_timestamp);
        SPDLOG_INFO(
            "Successfully synchronized with NTP server '{}'. "
            "Server timestamp: {}, "
            "local timestamp: {}, "
            "calculated offset: {} seconds",
            server, server_timestamp, client_timestamp, offset_seconds_.load());
        return true;
      }
    } catch (...) {
      SPDLOG_WARN("Unknown error during NTP request to {}:{}", server, port);
    }
  }
  SPDLOG_ERROR(
      "Failed to get time from NTP server. "
      "Using local system time without synchronization");
  return false;
}

}  // namespace fptn::time
