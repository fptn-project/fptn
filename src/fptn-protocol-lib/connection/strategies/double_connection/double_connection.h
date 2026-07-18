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
#include <vector>

#include <boost/asio/awaitable.hpp>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

class DoubleConnection : public BaseStrategyConnection {
 private:
  struct Channel {
    std::uint64_t connection_id;
    std::chrono::system_clock::time_point close_at;
    fptn::protocol::https::WebsocketClientSPtr client;
  };

  struct Settings {
    std::size_t connection_count = 2;
    int lifetime_seconds = 600;
    int initial_lifetime_seconds = 300;
    int replacement_lead_seconds = 2;
    std::size_t max_connections = 3;
  };

 public:
  static std::unique_ptr<DoubleConnection> Create(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<DoubleConnection>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit DoubleConnection(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);
  ~DoubleConnection() override;

 public:
  void Start() override;

  void Stop() override;

  bool Send(fptn::common::network::IPPacketPtr packet) override;

  bool IsStarted() override;

  bool IsConnected() override;

 protected:
  boost::asio::awaitable<void> ManageCoroutine();

  boost::asio::awaitable<std::shared_ptr<Channel>> CreateNewConnection(
      int lifetime_seconds);

  boost::asio::awaitable<void> RemoveClosedConnections();

  boost::asio::awaitable<void> CreateMissingConnections();

  void NotifyConnectedOnce();

 private:
  mutable std::shared_mutex mutex_;

  std::atomic<bool> connected_notified_{false};
  std::atomic<std::uint64_t> connection_id_counter_{0};
  std::atomic<std::size_t> round_robin_cursor_{0};

  bool first_connection_created_ = false;

  const std::string session_id_;
  const Settings settings_;

  std::vector<std::shared_ptr<Channel>> connections_;
};

}  // namespace fptn::protocol::connection::strategies
