/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/system/command.h"

namespace fptn::common::network {

inline std::vector<std::string> GetServerIpAddresses() {
  std::vector<std::string> cmd_stdout;
  fptn::common::system::command::run(
      "ip -o addr show | awk '{print $4}' | cut -d'/' -f1", cmd_stdout);
  return cmd_stdout;
}

inline std::size_t DrainSocket(boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        1000)) {
  std::size_t total_drained = 0;
  const auto start_time = std::chrono::steady_clock::now();
  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};
    while (std::chrono::steady_clock::now() - start_time < drain_timeout) {
      if (socket.available() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }
      const std::size_t bytes =
          socket.read_some(boost::asio::buffer(buffer), ec);
      if (bytes > 0) {
        total_drained += bytes;
        continue;
      }
      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error during drain: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during socket drain: {}", e.what());
  }
  return total_drained;
}

inline boost::asio::awaitable<std::size_t> DrainSocketAsync(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        1000)) {
  std::size_t total_drained = 0;
  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};

    const auto start_time = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start_time < drain_timeout) {
      if (socket.available() == 0) {
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor,
            std::chrono::milliseconds(10));
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }
      const std::size_t bytes =
          co_await socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (bytes > 0) {
        total_drained += bytes;
        continue;
      }
      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error during drain: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during socket drain: {}", e.what());
  }

  co_return total_drained;
}

}  // namespace fptn::common::network
