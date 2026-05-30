/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/handshake/handshake_cache_manager.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/resolv.h"
#include "common/network/utils.h"

#include "fptn-protocol-lib/https/utils/tls/tls.h"

namespace {

boost::asio::awaitable<fptn::web::HandshakeResponse> FetchRealHandshake(
    const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data,
    const std::chrono::seconds& timeout) {
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::ip::tcp::socket target_socket(executor);

  constexpr std::size_t kMaxTotalSize = 65536;
  auto full_response = std::make_shared<std::vector<std::uint8_t>>();
  full_response->reserve(kMaxTotalSize);
  try {
    // DNS resolution
    const auto resolve_result =
        co_await fptn::common::network::AsyncResolve(sni, "443");

    if (!resolve_result.success()) {
      SPDLOG_WARN("DNS failed for {}: {}", sni, resolve_result.error.message());
      co_return nullptr;
    }

    // Connect to real server
    co_await boost::asio::async_connect(
        target_socket, resolve_result.results, boost::asio::use_awaitable);

    // Send client handshake
    co_await boost::asio::async_write(target_socket,
        boost::asio::buffer(client_handshake_data), boost::asio::use_awaitable);

    const auto server_response =
        co_await fptn::common::network::WaitForServerTlsHelloAsync(
            target_socket, timeout);
    if (server_response.has_value()) {
      *full_response = server_response.value();
    }
    SPDLOG_INFO("Received {} bytes from {}", full_response->size(), sni);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error fetching handshake from {}: {}", sni, e.what());
  }

  boost::system::error_code close_ec;
  target_socket.close(close_ec);

  co_return full_response;
}
}  // namespace

namespace fptn::web {

HandshakeCacheManager::HandshakeCacheManager(
    std::string default_domain, std::chrono::seconds cache_ttl)
    : cache_ttl_(cache_ttl),
      default_domain_(std::move(default_domain)) {}  // NOLINT

HandshakeResponse HandshakeCacheManager::CheckCache(
    const std::string& cache_key) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  const auto it = cache_.find(cache_key);
  if (it != cache_.end()) {
    const auto& entry = it->second;
    const auto now = std::chrono::steady_clock::now();
    if (now - entry.timestamp < cache_ttl_) {
      return it->second.data;
    }
    cache_.erase(it);
  }
  return nullptr;
}

boost::asio::awaitable<HandshakeResponse> HandshakeCacheManager::GetHandshake(
    const std::string& sni,
    const std::uint8_t* buffer_ptr,
    std::size_t size,
    const std::chrono::seconds& timeout) {
  std::vector<std::uint8_t> client_handshake_data(
      buffer_ptr, buffer_ptr + size);

  const auto cached_response = CheckCache(sni);
  if (cached_response && !cached_response->empty()) {
    SPDLOG_INFO("Cache hit for SNI: {} (TLS fingerprint size: {})", sni,
        cached_response->size());
    co_return cached_response;
  }

  HandshakeResponse response =
      co_await FetchRealHandshake(sni, client_handshake_data, timeout);
  if (!response) {
    SPDLOG_WARN(
        "Failed to fetch handshake from original SNI: {}, trying default "
        "domain: {}",
        sni, default_domain_);

    // RET
    const auto default_cached_response = CheckCache(default_domain_);
    if (default_cached_response && !default_cached_response->empty()) {
      SPDLOG_INFO("Returning cached handshake for SNI: {} (using cache)",
          default_domain_);
      co_return default_cached_response;
    }

    // Get new
    // Generate fresh ClientHello with correct SNI for fallback domain.
    // Do NOT forward client_handshake_data here — it contains the fake SNI
    // which causes the fallback server to send only a partial ServerHello.
    const auto fallback_hello =
        fptn::protocol::https::utils::GenerateDecoyTlsHandshake(
            default_domain_);
    response =
        co_await FetchRealHandshake(default_domain_, fallback_hello, timeout);
    if (response && !response->empty()) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex
      cache_[default_domain_] = CacheEntry{
          .data = response, .timestamp = std::chrono::steady_clock::now()};
      SPDLOG_INFO("Successfully fetched handshake from default domain: {}",
          default_domain_);
    }
  }

  if (response && !response->empty()) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex
    cache_[sni] = CacheEntry{
        .data = response, .timestamp = std::chrono::steady_clock::now()};
    SPDLOG_INFO(
        "Cached handshake response for SNI: {}, "
        "size: {} bytes",
        sni, response->size());
    co_return response;
  }
  SPDLOG_WARN("Failed to fetch handshake from real server for SNI: {}", sni);
  co_return HandshakeResponse();
}

}  // namespace fptn::web
