/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace fptn::time {

using NtpServers = std::vector<std::pair<std::string, std::uint16_t>>;

class TimeProvider final {
 public:
  static TimeProvider* Instance() {
    static TimeProvider provider;
    return &provider;
  }

  std::string Rfc7231Date() const;
  std::int32_t OffsetSeconds() const;
  std::uint32_t NowTimestamp() const;
  bool SyncWithNtp();

 protected:
  explicit TimeProvider(
      NtpServers servers = {
        {"pool.ntp.org", 123},
        {"ru.pool.ntp.org", 123},
        {"ntp.ix.ru", 123}
      });
  bool Refresh();

 private:
  mutable std::mutex mutex_;
  const NtpServers servers_;

  std::atomic<std::int32_t> offset_seconds_;
};

}  // namespace fptn::time
