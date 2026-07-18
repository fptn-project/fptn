/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/double_connection/double_connection.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace fptn::protocol::connection::strategies {

DoubleConnection::DoubleConnection(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
      session_id_(fptn::common::utils::GenerateRandomString(32)) {}  // NOLINT

DoubleConnection::~DoubleConnection() {
  DoubleConnection::Stop();  // NOLINT
}

void DoubleConnection::Start() {
  SetRunningStatus(true);
  boost::asio::co_spawn(
      GetIOContext(),
      [this]() -> boost::asio::awaitable<void> { co_await ManageCoroutine(); },
      boost::asio::detached);
  RunEventLoop();
}

void DoubleConnection::Stop() {
  const std::unique_lock lock(mutex_);  // mutex

  SetRunningStatus(false);
  for (const auto& channel : connections_) {
    if (channel && channel->client) {
      channel->client->Stop();
    }
  }
  connections_.clear();
}

bool DoubleConnection::Send(fptn::common::network::IPPacketPtr packet) {
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
  return channel && channel->client && channel->client->Send(std::move(packet));
}

bool DoubleConnection::IsStarted() { return RunningStatus(); }

bool DoubleConnection::IsConnected() {
  const std::shared_lock lock(mutex_);  // read-only lock

  return std::ranges::any_of(connections_, [](const auto& channel) {
    return channel && channel->client && channel->client->IsStarted();
  });
}

boost::asio::awaitable<void> DoubleConnection::ManageCoroutine() {
  boost::asio::steady_timer timer(GetIOContext());
  while (IsStarted()) {
    try {
      co_await boost::asio::post(boost::asio::use_awaitable);

      co_await RemoveClosedConnections();

      co_await CreateMissingConnections();

      NotifyConnectedOnce();
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Error in ManageCoroutine: {}", e.what());
    }
    timer.expires_after(std::chrono::seconds(1));
    co_await timer.async_wait(boost::asio::use_awaitable);
  }
  co_return;
}

void DoubleConnection::NotifyConnectedOnce() {
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

boost::asio::awaitable<std::shared_ptr<DoubleConnection::Channel>>
DoubleConnection::CreateNewConnection(int lifetime_seconds) {
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

    channel->client = std::make_shared<fptn::protocol::https::WebsocketClient>(
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

boost::asio::awaitable<void> DoubleConnection::RemoveClosedConnections() {
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
        [closed_connections =
                std::move(dead_connections)]() -> boost::asio::awaitable<void> {
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

boost::asio::awaitable<void> DoubleConnection::CreateMissingConnections() {
  if (!IsStarted()) {
    co_return;
  }

  const auto lead = std::chrono::seconds(settings_.replacement_lead_seconds);

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

  const std::size_t target = settings_.connection_count;
  for (std::size_t i = healthy_count; i < target; i++) {
    {
      const std::shared_lock lock(mutex_);  // read-only lock
      if (connections_.size() >= settings_.max_connections) {
        break;
      }
    }

    bool use_initial_lifetime = false;
    {
      const std::shared_lock lock(mutex_);  // read-only lock
      use_initial_lifetime = !first_connection_created_;
    }
    const int lifetime_seconds = use_initial_lifetime
                                     ? settings_.initial_lifetime_seconds
                                     : settings_.lifetime_seconds;

    auto channel = co_await CreateNewConnection(lifetime_seconds);
    if (channel) {
      const std::unique_lock lock(mutex_);  // mutex
      connections_.push_back(std::move(channel));
      first_connection_created_ = true;
    }
  }
  co_return;
}

}  // namespace fptn::protocol::connection::strategies
