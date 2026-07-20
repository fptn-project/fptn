/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <utility>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

class PersistentTunnel : public BaseStrategyConnection {
 public:
  static std::unique_ptr<PersistentTunnel> Create(
      std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<PersistentTunnel>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit PersistentTunnel(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);

  ~PersistentTunnel() override;

 public:
  void Start() override;

  void Stop() override;

  bool Send(fptn::common::network::IPPacketPtr packet) override;

  bool IsStarted() override;

  bool IsConnected() override;

 private:
  mutable std::mutex mutex_;

  const std::string session_id_;

  fptn::protocol::https::WebsocketClientSPtr websocket_client_;
};

}  // namespace fptn::protocol::connection::strategies
