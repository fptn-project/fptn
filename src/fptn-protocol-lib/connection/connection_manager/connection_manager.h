/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::protocol::connection {

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

class ConnectionManager final {
 public:
  ConnectionManager(strategies::ConnectionStrategy connection_strategy_type,
      fptn::protocol::https::ConnectionConfig config);

  ~ConnectionManager();

  void SetRecvBatchIPPacketCallback(
      const fptn::protocol::https::OnIPRecvBatchPacketCallback& callback);

  void SetRecvIPPacketCallback(
      const fptn::protocol::https::OnIPRecvPacketCallback& callback);

  void SetAccessToken(const std::string& token);

  bool Login(const std::string& username,
      const std::string& password,
      int timeout_sec = 15);

  std::pair<IPv4Address, IPv6Address> GetDns();

  bool Start();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet) const;
  bool IsStarted() const;
  bool IsConnected() const;

  const std::string& LatestError() const;

 protected:
  void Run();

 private:
  std::thread th_;
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  std::string jwt_access_token_;
  std::string latest_error_;
  std::size_t reconnection_attempts_;

  strategies::ConnectionStrategy connection_strategy_type_;
  fptn::protocol::https::ConnectionConfig config_;

  IPv4Address dns_ipv4_;
  IPv6Address dns_ipv6_;

  strategies::StrategyConnectionPtr strategy_connection_;
};

using ConnectionManagerPtr = std::unique_ptr<ConnectionManager>;

}  // namespace fptn::protocol::connection
