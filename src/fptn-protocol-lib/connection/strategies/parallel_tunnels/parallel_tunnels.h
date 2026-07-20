/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

template <std::size_t ConnectionCount, int LifetimeSeconds>
class ParallelTunnels : public BaseStrategyConnection {
  static_assert(
      ConnectionCount >= 2, "ParallelTunnels needs at least 2 connections");
  static_assert(LifetimeSeconds > 0, "Socket lifetime must be positive");

 private:
  struct Channel {
    std::uint64_t connection_id;
    std::chrono::system_clock::time_point close_at;
    fptn::protocol::https::WebsocketClientSPtr client;
  };

  static constexpr int kReplacementLeadSeconds = 2;
  static constexpr std::size_t kMaxConnections = ConnectionCount + 1;

 public:
  static std::unique_ptr<ParallelTunnels> Create(
      std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<ParallelTunnels>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit ParallelTunnels(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config)
      : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
        session_id_(fptn::common::utils::GenerateRandomString(64)) {}

  ~ParallelTunnels() override {
    ParallelTunnels::Stop();  // NOLINT
  }

 public:
  void Start() override {
    SetRunningStatus(true);
    boost::asio::co_spawn(
        GetIOContext(),
        [this]() -> boost::asio::awaitable<void> {
          co_await ManageCoroutine();
        },
        boost::asio::detached);
    RunEventLoop();
  }

  void Stop() override {
    const std::unique_lock lock(mutex_);  // mutex

    SetRunningStatus(false);
    for (const auto& channel : connections_) {
      if (channel && channel->client) {
        channel->client->Stop();
      }
    }
    connections_.clear();
  }

  bool Send(fptn::common::network::IPPacketPtr packet) override {
    if (!IsStarted()) {
      return false;
    }

    std::shared_ptr<Channel> channel;
    {
      const std::shared_lock lock(mutex_);  // read-only lock

      if (connections_.empty()) {
        return false;
      }
      const std::size_t count = connections_.size();
      const std::size_t start = round_robin_cursor_.fetch_add(1);
      for (std::size_t i = 0; i < count; ++i) {
        const auto& candidate = connections_[(start + i) % count];
        if (candidate && candidate->client && candidate->client->IsStarted()) {
          channel = candidate;
          break;
        }
      }
    }
    return channel && channel->client &&
           channel->client->Send(std::move(packet));
  }

  bool IsStarted() override { return RunningStatus(); }

  bool IsConnected() override {
    const std::shared_lock lock(mutex_);  // read-only lock

    return std::ranges::any_of(connections_, [](const auto& channel) {
      return channel && channel->client && channel->client->IsStarted();
    });
  }

  bool IsPoolEmpty() const {
    const std::shared_lock lock(mutex_);  // read-only lock

    return connections_.empty();
  }

 protected:
  boost::asio::awaitable<void> ManageCoroutine() {
    boost::asio::steady_timer timer(GetIOContext());
    while (IsStarted()) {
      try {
        co_await boost::asio::post(boost::asio::use_awaitable);

        co_await RemoveClosedConnections();

        co_await CreateMissingConnections();

        if (IsPoolEmpty()) {
          SPDLOG_ERROR("All connections are lost. Reconnecting");
          SetRunningStatus(false);
          break;
        }

        NotifyConnectedOnce();
      } catch (const std::exception& e) {
        SPDLOG_ERROR("Error in ManageCoroutine: {}", e.what());
      }
      timer.expires_after(std::chrono::seconds(1));
      co_await timer.async_wait(boost::asio::use_awaitable);
    }
    co_return;
  }

  boost::asio::awaitable<std::shared_ptr<Channel>> CreateNewConnection(
      int lifetime_seconds) {
    try {
      auto channel = std::make_shared<Channel>();
      channel->connection_id = ++connection_id_counter_;
      channel->close_at = std::chrono::system_clock::now() +
                          std::chrono::seconds(lifetime_seconds);

      auto config = Config();
      config.common.on_connected_callback = nullptr;
      config.common.session_id = session_id_;
      config.common.send_duration_ms = 0;
      config.common.ttl_ms = 0;

      channel->client =
          std::make_shared<fptn::protocol::https::WebsocketClient>(
              JWTAccessToken(), config, GetIOContext());

      channel->client->Run();
      co_await boost::asio::post(boost::asio::use_awaitable);

      boost::asio::steady_timer timer(GetIOContext());
      for (int i = 0; i < 10; i++) {
        if (channel->client->IsStarted()) {
          SPDLOG_INFO("Connection #{} READY (lifetime {}s)",
              channel->connection_id, lifetime_seconds);
          co_return channel;
        }
        if (channel->client->IsStopped()) {
          break;
        }
        timer.expires_after(std::chrono::milliseconds(500));
        co_await timer.async_wait(boost::asio::use_awaitable);
      }
      channel->client->Stop();
      SPDLOG_ERROR("Connection #{} FAILED to start", channel->connection_id);
    } catch (const std::exception& err) {
      SPDLOG_ERROR("Failed to create connection: {}", err.what());
    }
    co_return nullptr;
  }

  boost::asio::awaitable<void> RemoveClosedConnections() {
    std::vector<std::shared_ptr<Channel>> dead_connections;
    {
      const std::unique_lock lock(mutex_);  // mutex

      const auto now = std::chrono::system_clock::now();
      for (auto it = connections_.begin(); it != connections_.end();) {
        const auto& channel = *it;
        const bool dead = !channel || !channel->client ||
                          channel->client->IsStopped() ||
                          now >= channel->close_at;
        if (dead) {
          dead_connections.push_back(channel);
          it = connections_.erase(it);
        } else {
          ++it;
        }
      }
    }
    if (!dead_connections.empty()) {
      boost::asio::co_spawn(
          GetIOContext(),
          [closed_connections = std::move(
               dead_connections)]() -> boost::asio::awaitable<void> {
            for (const auto& channel : closed_connections) {
              if (channel && channel->client) {
                channel->client->Stop();
              }
            }
            co_return;
          },
          boost::asio::detached);
    }
    co_return;
  }

  boost::asio::awaitable<void> CreateMissingConnections() {
    if (!IsStarted()) {
      co_return;
    }

    const auto lead = std::chrono::seconds(kReplacementLeadSeconds);

    std::size_t healthy_count = 0;
    {
      const std::shared_lock lock(mutex_);  // read-only lock

      const auto deadline = std::chrono::system_clock::now() + lead;
      healthy_count =
          std::ranges::count_if(connections_, [&deadline](const auto& channel) {
            return channel && channel->client && channel->client->IsStarted() &&
                   channel->close_at > deadline;
          });
    }

    for (std::size_t i = healthy_count; i < ConnectionCount; i++) {
      {
        const std::shared_lock lock(mutex_);  // read-only lock
        if (connections_.size() >= kMaxConnections) {
          break;
        }
      }

      auto channel = co_await CreateNewConnection(NextLifetimeSeconds());
      if (!channel) {
        break;
      }
      {
        const std::unique_lock lock(mutex_);  // mutex
        connections_.push_back(std::move(channel));
      }
    }
    co_return;
  }

  // Places the new connection one slot away from the ones already scheduled, so
  // the pool keeps closing its sockets one at a time instead of all at once.
  int NextLifetimeSeconds() const {
    constexpr int kSlotSeconds =
        LifetimeSeconds / static_cast<int>(ConnectionCount);

    std::vector<int> remaining;
    {
      const std::shared_lock lock(mutex_);  // read-only lock

      const auto now = std::chrono::system_clock::now();
      for (const auto& channel : connections_) {
        if (!channel) {
          continue;
        }
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            channel->close_at - now)
                                 .count();
        if (seconds > 0 && seconds <= LifetimeSeconds) {
          remaining.push_back(static_cast<int>(seconds));
        }
      }
    }
    if (remaining.empty()) {
      return kSlotSeconds;
    }
    std::ranges::sort(remaining);

    const int appended = remaining.back() + kSlotSeconds;
    if (appended <= LifetimeSeconds) {
      return appended;
    }

    int widest_gap = remaining.front();
    int lifetime_seconds = widest_gap / 2;
    for (std::size_t i = 1; i < remaining.size(); i++) {
      const int gap = remaining[i] - remaining[i - 1];
      if (gap > widest_gap) {
        widest_gap = gap;
        lifetime_seconds = remaining[i - 1] + gap / 2;
      }
    }
    return lifetime_seconds;
  }

  void NotifyConnectedOnce() {
    if (connected_notified_.load()) {
      return;
    }

    bool any_ready = false;
    {
      const std::shared_lock lock(mutex_);  // read-only lock
      any_ready = std::ranges::any_of(connections_, [](const auto& channel) {
        return channel && channel->client && channel->client->IsStarted();
      });
    }
    if (!any_ready) {
      return;
    }

    connected_notified_ = true;
    const auto& callback = Config().common.on_connected_callback;
    if (callback) {
      callback();
    }
  }

 private:
  mutable std::shared_mutex mutex_;

  std::atomic<bool> connected_notified_{false};
  std::atomic<std::uint64_t> connection_id_counter_{0};
  std::atomic<std::size_t> round_robin_cursor_{0};

  const std::string session_id_;

  std::vector<std::shared_ptr<Channel>> connections_;
};

using DualTunnel = ParallelTunnels<2, 600>;
using TripleTunnel = ParallelTunnels<3, 600>;

}  // namespace fptn::protocol::connection::strategies
