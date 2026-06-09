/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

namespace fptn::web {

using HandshakeResponse = std::shared_ptr<std::vector<std::uint8_t>>;

class HandshakeCacheManager final {
 public:
  explicit HandshakeCacheManager(std::string default_domain,
      std::chrono::seconds cache_ttl = std::chrono::seconds(1200));

  boost::asio::awaitable<HandshakeResponse> GetHandshake(const std::string& sni,
      const std::uint8_t* buffer_ptr,
      std::size_t size,
      const std::chrono::seconds& timeout);

  HandshakeResponse CheckCache(const std::string& cache_key);

 private:
  struct CacheEntry {
    HandshakeResponse data;
    std::chrono::steady_clock::time_point timestamp;
  };

  mutable std::mutex mutex_;

  std::chrono::seconds cache_ttl_;

  const std::string default_domain_;

  std::unordered_map<std::string, CacheEntry> cache_;
};

using HandshakeCacheManagerSPtr = std::shared_ptr<HandshakeCacheManager>;

}  // namespace fptn::web
