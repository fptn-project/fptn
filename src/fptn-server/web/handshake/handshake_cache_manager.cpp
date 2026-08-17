/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/handshake/handshake_cache_manager.h"

#include <array>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"
#include "common/network/resolv.h"
#include "common/network/utils.h"

#include "fptn-protocol-lib/https/utils/tls/tls.h"

namespace {

// Forwards the client's own ClientHello to the decoy and returns its answer.
//
// This is the Reality property itself: the decoy must see the genuine browser
// fingerprint the client produced, not one of ours. The price is that the
// client's private key is not ours, so the flight cannot be decrypted and its
// end cannot be derived by parsing. The only sound stopping condition left is
// structural plus silence: the buffer holds a whole number of TLS records and
// the decoy has stopped writing. A short answer is not fatal — the client's
// obfuscator resynchronises past whatever it did not consume.
boost::asio::awaitable<fptn::web::HandshakeResponse> FetchForwardedHandshake(
    const std::string& sni,
    const std::vector<std::uint8_t>& client_hello,
    const std::chrono::seconds& timeout) {
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::ip::tcp::socket target_socket(executor);

  constexpr std::size_t kMaxTotalSize = 65536;
  constexpr auto kQuietPeriod = std::chrono::milliseconds(300);
  auto full_response = std::make_shared<std::vector<std::uint8_t>>();
  try {
    auto fetch = [&]() -> boost::asio::awaitable<void> {
      const auto resolve_result =
          co_await fptn::common::network::AsyncResolve(sni, "443");
      if (!resolve_result.success()) {
        SPDLOG_WARN(
            "DNS failed for {}: {}", sni, resolve_result.error.message());
        co_return;
      }
      co_await boost::asio::async_connect(
          target_socket, resolve_result.results, boost::asio::use_awaitable);
      co_await boost::asio::async_write(target_socket,
          boost::asio::buffer(client_hello), boost::asio::use_awaitable);

      std::vector<std::uint8_t> data;
      data.reserve(kMaxTotalSize);
      std::array<std::uint8_t, 8192> buf{};
      using boost::asio::experimental::awaitable_operators::operator||;
      while (data.size() < kMaxTotalSize) {
        boost::asio::steady_timer quiet(executor, kQuietPeriod);
        boost::system::error_code read_ec;
        const auto race = co_await(  // NOLINT(whitespace/parens)
            target_socket.async_read_some(boost::asio::buffer(buf),
                boost::asio::redirect_error(
                    boost::asio::use_awaitable, read_ec)) ||
            quiet.async_wait(boost::asio::use_awaitable));
        if (race.index() == 1) {
          break;
        }
        const std::size_t bytes = std::get<0>(race);
        if (read_ec || bytes == 0) {
          break;
        }
        data.insert(data.end(), buf.begin(), buf.begin() + bytes);
      }

      if (fptn::common::network::IsRecordAlignedServerFlight(data)) {
        *full_response = std::move(data);
      } else {
        SPDLOG_WARN("Decoy {} answered {} bytes that do not form whole TLS "
                    "records", sni, data.size());
      }
    };

    boost::asio::steady_timer deadline(executor, timeout);
    using boost::asio::experimental::awaitable_operators::operator||;
    const auto race = co_await(  // NOLINT(whitespace/parens)
        fetch() || deadline.async_wait(boost::asio::use_awaitable));
    if (race.index() == 1) {
      SPDLOG_WARN("Timeout forwarding handshake to {}", sni);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error forwarding handshake to {}: {}", sni, e.what());
  }

  boost::system::error_code close_ec;
  target_socket.close(close_ec);

  // cppcheck-suppress knownConditionTrueFalse
  if (full_response->empty()) {
    co_return nullptr;
  }
  SPDLOG_INFO(
      "Forwarded handshake to {}: {} bytes", sni, full_response->size());
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
    const std::chrono::seconds& target_timeout,
    const std::chrono::seconds& fallback_timeout) {
  const std::vector<std::uint8_t> client_hello(buffer_ptr, buffer_ptr + size);

  const auto cached_response = CheckCache(sni);
  if (cached_response && !cached_response->empty()) {
    SPDLOG_INFO("Cache hit for SNI: {} (TLS fingerprint size: {})", sni,
        cached_response->size());
    co_return cached_response;
  }

  HandshakeResponse response =
      co_await FetchForwardedHandshake(sni, client_hello, target_timeout);
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
    response = co_await FetchForwardedHandshake(default_domain_,
        fptn::protocol::https::utils::GenerateDecoyTlsHandshake(
            default_domain_),
        fallback_timeout);
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
