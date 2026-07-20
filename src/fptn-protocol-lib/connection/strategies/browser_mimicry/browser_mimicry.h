/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

enum class ConnectionStatus : int { kCreating, kSending, kReceiving, kError };
struct ConnectionContext {
  std::uint64_t connection_id;
  ConnectionStatus status;

  struct {
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_used_at;
    std::chrono::system_clock::time_point
        send_mode_until;  // До когда может отправлять
    std::chrono::system_clock::time_point expire_after;  // Когда умрет
  } timings;

  struct {
    std::size_t packets_sent = 0;
    std::size_t packets_received = 0;
    std::size_t bytes_sent = 0;
    std::size_t bytes_received = 0;
  } stats;

  std::shared_ptr<fptn::protocol::https::WebsocketClient> client;

  explicit ConnectionContext(int send_mode_seconds, int ttl_seconds)
      : connection_id(0), status(ConnectionStatus::kCreating) {
    static std::uint64_t connection_id_counter = 0;
    connection_id = ++connection_id_counter;

    const auto now = std::chrono::system_clock::now();
    timings.created_at = now;
    timings.last_used_at = now;
    timings.send_mode_until = now + std::chrono::seconds(send_mode_seconds);
    timings.expire_after = now + std::chrono::seconds(ttl_seconds);
  }

  [[nodiscard]]
  bool CanSend() const noexcept {
    return status == ConnectionStatus::kSending &&
           std::chrono::system_clock::now() < timings.send_mode_until;
  }

  [[nodiscard]]
  bool SendTimeExpired() const noexcept {
    return std::chrono::system_clock::now() >= timings.send_mode_until;
  }

  [[nodiscard]]
  bool IsExpired() const noexcept {
    return timings.expire_after <= std::chrono::system_clock::now();
  }
};

struct PoolSettings {
  std::size_t min_connections = 4;
  std::size_t max_connections = 8;

  struct {
    int min_seconds = 8;
    int max_seconds = 60;
  } connection_ttl_range;

  struct {
    int min_seconds = 5;
    int max_seconds = 30;
  } sending_mode_range;

  int min_sending_seconds = 1;
};

using ConnectionList = std::vector<std::shared_ptr<ConnectionContext>>;

class BrowserMimicry : public BaseStrategyConnection {
 public:
  static std::unique_ptr<BrowserMimicry> Create(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<BrowserMimicry>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit BrowserMimicry(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);
  ~BrowserMimicry() override;

 protected:
  boost::asio::awaitable<void> ManagePoolCoroutine();

  boost::asio::awaitable<std::shared_ptr<ConnectionContext>>
  CreateNewConnection(int sending_mode_seconds, int ttl_seconds);

  boost::asio::awaitable<void> RemoveExpiredConnections();

  boost::asio::awaitable<void> UpdateConnectionsStatus();

  boost::asio::awaitable<void> CreateMissingConnections();

  void NotifyConnectedOnce();

 private:
  int GetRandomInt(const int min, const int max) const;

 public:
  void Start() override;

  void Stop() override;  // NOLINT

  bool Send(fptn::common::network::IPPacketPtr packet) override;

  bool IsStarted() override;

  bool IsConnected() override;

  bool IsPoolEmpty() const;

 private:
  mutable std::shared_mutex mutex_;
  mutable std::mutex random_mutex_;
  mutable std::mt19937 random_generator_;

  std::atomic<bool> connected_notified_{false};

  const std::string session_id_;

  const PoolSettings settings_;

  ConnectionList all_connections_;
  ConnectionList getting_data_connections_;
  ConnectionList sending_data_connections_;
};

}  // namespace fptn::protocol::connection::strategies
