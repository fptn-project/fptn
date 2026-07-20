/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/persistent_tunnel/persistent_tunnel.h"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include "common/utils/utils.h"

namespace fptn::protocol::connection::strategies {

PersistentTunnel::PersistentTunnel(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
      session_id_(fptn::common::utils::GenerateRandomString(64)) {}  // NOLINT

PersistentTunnel::~PersistentTunnel() {
  PersistentTunnel::Stop();  // NOLINT
}

void PersistentTunnel::Start() {
  auto config = Config();
  config.common.session_id = session_id_;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex
    websocket_client_ =
        std::make_unique<fptn::protocol::https::WebsocketClient>(
            JWTAccessToken(), std::move(config), GetIOContext());
  }

  SetRunningStatus(true);
  websocket_client_->Run();

  const auto* ws = websocket_client_.get();
  boost::asio::io_context& ioc = GetIOContext();
  constexpr std::chrono::milliseconds kIdle(1);
  while (RunningStatus() && ws && !ws->IsStopped()) {
    const std::size_t processed = ioc.poll_one();
    if (processed == 0) {
      std::this_thread::sleep_for(kIdle);
    }
  }
  SetRunningStatus(false);
  if (!ioc.stopped()) {
    ioc.stop();
  }
}

void PersistentTunnel::Stop() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  SetRunningStatus(false);

  if (websocket_client_) {
    websocket_client_->Stop();
  }
}

bool PersistentTunnel::Send(fptn::common::network::IPPacketPtr packet) {
  if (websocket_client_) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (RunningStatus()) {
      // cppcheck-suppress knownConditionTrueFalse
      return websocket_client_ && websocket_client_->Send(std::move(packet));
    }
  }
  return false;
}

bool PersistentTunnel::IsStarted() { return RunningStatus(); }

bool PersistentTunnel::IsConnected() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return websocket_client_ && websocket_client_->IsStarted();
}

}  // namespace fptn::protocol::connection::strategies
