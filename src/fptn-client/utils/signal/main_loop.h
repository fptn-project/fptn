#pragma once

/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <boost/asio.hpp>
#include <boost/process.hpp>

#include "vpn/vpn_manager.h"

namespace fptn::utils {

void WaitForSignal(fptn::vpn::VpnManager& vpn_client) {
  boost::asio::io_context io_context;
  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
#ifndef _WIN32
  signals.add(SIGHUP);
#endif

  boost::asio::steady_timer check_timer(io_context);

  std::function<void()> check_connection = [&]() {
    if (!vpn_client.IsStarted()) {
      SPDLOG_ERROR("VPN connection lost! Exiting...");
      io_context.stop();
      return;
    }

    check_timer.expires_after(std::chrono::seconds(1));
    check_timer.async_wait([&](const boost::system::error_code& ec) {
      if (!ec) {
        check_connection();
      }
    });
  };

  signals.async_wait([&](auto, auto) { io_context.stop(); });
  check_timer.expires_after(std::chrono::seconds(1));
  check_timer.async_wait([&](const boost::system::error_code& ec) {
    if (!ec) {
      check_connection();
    }
  });
  io_context.run();
}
}  // namespace fptn::utils
