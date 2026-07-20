/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/rolling_tunnel/rolling_tunnel.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace fptn::protocol::connection::strategies {

RollingTunnel::RollingTunnel(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
      session_id_(fptn::common::utils::GenerateRandomString(64)) {}  // NOLINT

RollingTunnel::~RollingTunnel() {
  RollingTunnel::Stop();  // NOLINT
}

void RollingTunnel::Start() {
  SetRunningStatus(true);
  boost::asio::co_spawn(
      GetIOContext(),
      [this]() -> boost::asio::awaitable<void> { co_await ManageCoroutine(); },
      boost::asio::detached);
  RunEventLoop();
}

void RollingTunnel::Stop() {
  const std::unique_lock lock(mutex_);  // mutex

  SetRunningStatus(false);
  if (active_connection_) {
    active_connection_->Stop();
    active_connection_.reset();
  }
}

bool RollingTunnel::Send(fptn::common::network::IPPacketPtr packet) {
  if (!IsStarted()) {
    return false;
  }

  fptn::protocol::https::WebsocketClientSPtr connection;
  {
    const std::shared_lock lock(mutex_);  // read-only lock

    connection = active_connection_;
  }
  return connection && connection->Send(std::move(packet));
}

bool RollingTunnel::IsStarted() { return RunningStatus(); }

bool RollingTunnel::IsConnected() {
  const std::shared_lock lock(mutex_);  // read-only lock

  return active_connection_ && active_connection_->IsStarted();
}

bool RollingTunnel::HasActiveConnection() const {
  const std::shared_lock lock(mutex_);  // read-only lock

  return active_connection_ != nullptr;
}

bool RollingTunnel::ActiveConnectionIsStopped() const {
  const std::shared_lock lock(mutex_);  // read-only lock

  return active_connection_ && active_connection_->IsStopped();
}

boost::asio::awaitable<void> RollingTunnel::ManageCoroutine() {
  boost::asio::steady_timer timer(GetIOContext());
  while (IsStarted()) {
    try {
      co_await boost::asio::post(boost::asio::use_awaitable);

      if (ActiveConnectionIsStopped()) {
        SPDLOG_ERROR("Connection is lost. Reconnecting");
        SetRunningStatus(false);
        break;
      }

      const bool renew_required = !HasActiveConnection() ||
                                  std::chrono::system_clock::now() >= renew_at_;
      if (renew_required && !co_await RenewConnection()) {
        SPDLOG_ERROR("Failed to renew the connection. Reconnecting");
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

// Brings a replacement up while the current connection keeps carrying traffic,
// switches over once it is established and only then drops the old one.
boost::asio::awaitable<bool> RollingTunnel::RenewConnection() {
  auto connection = co_await CreateNewConnection();
  if (!connection) {
    co_return false;
  }

  fptn::protocol::https::WebsocketClientSPtr previous;
  {
    const std::unique_lock lock(mutex_);  // mutex

    previous = std::move(active_connection_);
    active_connection_ = connection;
    renew_at_ = std::chrono::system_clock::now() +
                std::chrono::seconds(kRenewAfterSeconds);
  }

  if (previous) {
    boost::asio::co_spawn(
        GetIOContext(),
        [previous]() -> boost::asio::awaitable<void> {
          previous->Stop();
          co_return;
        },
        boost::asio::detached);
  }
  co_return true;
}

boost::asio::awaitable<fptn::protocol::https::WebsocketClientSPtr>
RollingTunnel::CreateNewConnection() {
  try {
    auto config = Config();
    config.common.on_connected_callback = nullptr;
    config.common.session_id = session_id_;
    config.common.send_duration_ms = 0;
    config.common.ttl_ms = 0;

    const std::uint64_t connection_id = ++connection_id_counter_;
    auto connection = std::make_shared<fptn::protocol::https::WebsocketClient>(
        JWTAccessToken(), config, GetIOContext());

    connection->Run();
    co_await boost::asio::post(boost::asio::use_awaitable);

    boost::asio::steady_timer timer(GetIOContext());
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(kConnectBudgetSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
      if (connection->IsStarted()) {
        SPDLOG_INFO("Connection #{} READY", connection_id);
        co_return connection;
      }
      if (connection->IsStopped()) {
        break;
      }
      timer.expires_after(std::chrono::milliseconds(500));
      co_await timer.async_wait(boost::asio::use_awaitable);
    }
    connection->Stop();
    SPDLOG_ERROR("Connection #{} FAILED to start", connection_id);
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to create connection: {}", err.what());
  }
  co_return nullptr;
}

void RollingTunnel::NotifyConnectedOnce() {
  if (connected_notified_.load() || !IsConnected()) {
    return;
  }

  connected_notified_ = true;
  const auto& callback = Config().common.on_connected_callback;
  if (callback) {
    callback();
  }
}

}  // namespace fptn::protocol::connection::strategies
