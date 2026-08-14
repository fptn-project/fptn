/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/browser_mimicry/browser_mimicry.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace {

bool RemoveFromConnectionList(
    fptn::protocol::connection::strategies::ConnectionList& connections,
    const std::uint64_t id) {
  const auto it = std::ranges::find_if(connections,
      [&id](const auto& conn) { return conn->connection_id == id; });
  if (it != connections.end()) {
    connections.erase(it);
    return true;
  }
  return false;
}

}  // namespace

namespace fptn::protocol::connection::strategies {

BrowserMimicry::BrowserMimicry(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
      random_generator_(std::random_device{}()),                     // NOLINT
      session_id_(fptn::common::utils::GenerateRandomString(64)) {}  // NOLINT

BrowserMimicry::~BrowserMimicry() {
  BrowserMimicry::Stop();  // NOLINT
}

void BrowserMimicry::Start() {
  SetRunningStatus(true);
  boost::asio::co_spawn(
      GetIOContext(),
      [this]() -> boost::asio::awaitable<void> {
        co_await ManagePoolCoroutine();
      },
      boost::asio::detached);
  RunEventLoop();
}

void BrowserMimicry::Stop() {
  const std::unique_lock lock(mutex_);  // mutex

  SetRunningStatus(false);
  for (const auto& ctx : all_connections_) {
    if (ctx && ctx->client) {
      ctx->status = ConnectionStatus::kError;
      ctx->client->Stop();
    }
  }

  all_connections_.clear();
  sending_data_connections_.clear();
  StopEventLoop();
  getting_data_connections_.clear();
}

bool BrowserMimicry::Send(fptn::common::network::IPPacketPtr packet) {
  if (!IsStarted()) {
    return false;
  }

  std::shared_ptr<ConnectionContext> connection;
  {
    const std::shared_lock lock(mutex_);  // read-only lock

    const auto& pool = !sending_data_connections_.empty()
                           ? sending_data_connections_
                           : getting_data_connections_;
    if (pool.empty()) {
      return false;
    }
    const int index = GetRandomInt(0, static_cast<int>(pool.size()) - 1);
    connection = pool[index];
  }
  return connection && connection->client &&
         connection->client->Send(std::move(packet));
}

bool BrowserMimicry::IsStarted() { return RunningStatus(); }

bool BrowserMimicry::IsConnected() {
  const std::shared_lock lock(mutex_);  // read-only lock

  return std::ranges::any_of(all_connections_, [](const auto& ctx) {
    return ctx && ctx->client && ctx->client->IsStarted();
  });
}

bool BrowserMimicry::IsPoolEmpty() const {
  const std::shared_lock lock(mutex_);  // read-only lock

  return all_connections_.empty();
}

boost::asio::awaitable<void> BrowserMimicry::ManagePoolCoroutine() {
  boost::asio::steady_timer timer(GetIOContext());
  while (IsStarted()) {
    try {
      co_await boost::asio::post(boost::asio::use_awaitable);

      co_await RemoveExpiredConnections();

      co_await UpdateConnectionsStatus();

      co_await CreateMissingConnections();

      if (IsPoolEmpty()) {
        SPDLOG_ERROR("All connections are lost. Reconnecting");
        SetRunningStatus(false);
        StopEventLoop();
        break;
      }

      NotifyConnectedOnce();
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Error in ManagePoolCoroutine: {}", e.what());
    }
    timer.expires_after(std::chrono::milliseconds(100));
    co_await timer.async_wait(boost::asio::use_awaitable);
  }

  co_return;
}

void BrowserMimicry::NotifyConnectedOnce() {
  if (connected_notified_.load()) {
    return;
  }

  bool any_ready = false;
  {
    const std::shared_lock lock(mutex_);  // read-only lock
    any_ready = std::ranges::any_of(all_connections_, [](const auto& ctx) {
      return ctx && ctx->client && ctx->client->IsStarted();
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

boost::asio::awaitable<std::shared_ptr<ConnectionContext>>
BrowserMimicry::CreateNewConnection(int sending_mode_seconds, int ttl_seconds) {
  try {
    auto connection =
        std::make_shared<ConnectionContext>(sending_mode_seconds, ttl_seconds);
    connection->status = ConnectionStatus::kCreating;

    auto config = Config();
    config.common.on_connected_callback = nullptr;
    config.common.session_id = session_id_;
    config.common.send_duration_ms =
        static_cast<std::uint64_t>(sending_mode_seconds) * 1000;
    config.common.ttl_ms = static_cast<std::uint64_t>(ttl_seconds) * 1000;

    connection->client =
        std::make_shared<fptn::protocol::https::WebsocketClient>(
            JWTAccessToken(), config, GetIOContext());

    connection->client->Run();
    co_await boost::asio::post(boost::asio::use_awaitable);

    boost::asio::steady_timer timer(GetIOContext());

    for (int i = 0; i < 10; i++) {
      if (connection->client->IsStarted()) {
        connection->status = ConnectionStatus::kCreating;
        SPDLOG_INFO("Connection #{} READY", connection->connection_id);
        co_return connection;
      }
      if (connection->client->IsStopped()) {
        break;
      }

      timer.expires_after(std::chrono::milliseconds(500));
      co_await timer.async_wait(boost::asio::use_awaitable);
    }
    connection->status = ConnectionStatus::kError;
    connection->client->Stop();
    SPDLOG_ERROR("Connection #{} FAILED to start", connection->connection_id);
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to create connection: {}", err.what());
  }
  co_return nullptr;
}

boost::asio::awaitable<void> BrowserMimicry::RemoveExpiredConnections() {
  std::vector<std::shared_ptr<ConnectionContext>> dead_connections;
  {
    const std::unique_lock lock(mutex_);  // mutex

    for (auto it = all_connections_.begin(); it != all_connections_.end();) {
      const auto& connection = *it;
      const bool dead = connection->IsExpired() ||
                        connection->status == ConnectionStatus::kError;
      if (dead) {
        dead_connections.push_back(connection);
        it = all_connections_.erase(it);

        RemoveFromConnectionList(
            getting_data_connections_, connection->connection_id);
        RemoveFromConnectionList(
            sending_data_connections_, connection->connection_id);
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
          for (const auto& connection : closed_connections) {
            if (connection && connection->client) {
              connection->client->Stop();
            }
          }
          co_return;
        },
        boost::asio::detached);
  }
  co_return;
}

boost::asio::awaitable<void> BrowserMimicry::UpdateConnectionsStatus() {
  const std::unique_lock lock(mutex_);  // mutex

  const auto now = std::chrono::system_clock::now();

  for (auto& connection : all_connections_) {
    const ConnectionStatus old_status = connection->status;

    if (connection->status == ConnectionStatus::kSending &&
        connection->SendTimeExpired()) {
      connection->status = ConnectionStatus::kReceiving;
    } else if (connection->status == ConnectionStatus::kCreating &&
               connection->client->IsStarted()) {
      if (connection->timings.send_mode_until > now) {
        connection->status = ConnectionStatus::kSending;
      } else {
        connection->status = ConnectionStatus::kReceiving;
      }
    }

    if (old_status != connection->status) {
      RemoveFromConnectionList(
          sending_data_connections_, connection->connection_id);
      RemoveFromConnectionList(
          getting_data_connections_, connection->connection_id);

      if (connection->status == ConnectionStatus::kSending) {
        sending_data_connections_.push_back(connection);
        SPDLOG_INFO("Connection #{} moved to SENDING (until {})",
            connection->connection_id,
            std::chrono::duration_cast<std::chrono::seconds>(
                connection->timings.send_mode_until - now)
                .count());
      } else if (connection->status == ConnectionStatus::kReceiving) {
        getting_data_connections_.push_back(connection);
        SPDLOG_INFO(
            "Connection #{} moved to RECEIVING", connection->connection_id);
      }
    }
  }
  co_return;
}

boost::asio::awaitable<void> BrowserMimicry::CreateMissingConnections() {
  if (!IsStarted()) {
    co_return;
  }

  constexpr auto kReplacementLead = std::chrono::seconds(3);

  int sending_count = 0;
  int receiving_count = 0;

  {
    const std::unique_lock lock(mutex_);  // mutex

    const auto deadline = std::chrono::system_clock::now() + kReplacementLead;
    for (const auto& connection : all_connections_) {
      if (connection->status == ConnectionStatus::kSending &&
          connection->timings.send_mode_until > deadline) {
        sending_count++;
      }
      if (connection->status == ConnectionStatus::kReceiving &&
          connection->timings.expire_after > deadline) {
        receiving_count++;
      }
    }
  }

  const int target_per_type =
      std::max(1, static_cast<int>(settings_.min_connections / 2));

  const int need_sending = std::max(0, target_per_type - sending_count);
  const int need_receiving = std::max(0, target_per_type - receiving_count);

  for (int i = 0; i < need_sending + need_receiving; i++) {
    if (all_connections_.size() >= settings_.max_connections) {
      break;
    }
    const bool refills_sending = (i < need_sending);
    const int send_time =
        refills_sending ? GetRandomInt(settings_.sending_mode_range.min_seconds,
                              settings_.sending_mode_range.max_seconds)
                        : settings_.min_sending_seconds;
    const int ttl = GetRandomInt(settings_.connection_ttl_range.min_seconds,
        settings_.connection_ttl_range.max_seconds);

    auto connection = co_await CreateNewConnection(send_time, ttl);
    if (!connection) {
      break;
    }
    {
      const std::unique_lock lock(mutex_);  // mutex

      all_connections_.push_back(std::move(connection));
    }
  }
  co_return;
}

int BrowserMimicry::GetRandomInt(const int min, const int max) const {
  const std::unique_lock<std::mutex> lock(random_mutex_);  // mutex

  std::uniform_int_distribution<int> dist(min, max);
  return dist(random_generator_);
}

}  // namespace fptn::protocol::connection::strategies
