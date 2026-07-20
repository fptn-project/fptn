/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

class RollingTunnel : public BaseStrategyConnection {
 private:
  static constexpr int kRenewAfterSeconds = 9 * 60;
  static constexpr int kConnectBudgetSeconds = 60;

 public:
  static std::unique_ptr<RollingTunnel> Create(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<RollingTunnel>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit RollingTunnel(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);
  ~RollingTunnel() override;

 public:
  void Start() override;

  void Stop() override;

  bool Send(fptn::common::network::IPPacketPtr packet) override;

  bool IsStarted() override;

  bool IsConnected() override;

 protected:
  boost::asio::awaitable<void> ManageCoroutine();

  boost::asio::awaitable<fptn::protocol::https::WebsocketClientSPtr>
  CreateNewConnection();

  boost::asio::awaitable<bool> RenewConnection();

  void NotifyConnectedOnce();

 private:
  bool HasActiveConnection() const;
  bool ActiveConnectionIsStopped() const;

  mutable std::shared_mutex mutex_;

  std::atomic<bool> connected_notified_{false};
  std::atomic<std::uint64_t> connection_id_counter_{0};

  const std::string session_id_;

  fptn::protocol::https::WebsocketClientSPtr active_connection_;
  std::chrono::system_clock::time_point renew_at_;
};

}  // namespace fptn::protocol::connection::strategies
