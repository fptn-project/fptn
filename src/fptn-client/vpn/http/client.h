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

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::vpn::http {

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

class Client final {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  using OnIPAssignedCallback =
      std::function<void(const IPv4Address& ip_v4, const IPv6Address& ip_v6)>;

 public:
  explicit Client(fptn::protocol::https::WebsocketClient::Config config);
  ~Client();
  void SetAccessToken(const std::string& token);
  bool Login(const std::string& username,
      const std::string& password,
      int timeout_sec = 5);
  std::pair<IPv4Address, IPv6Address> GetDns();
  bool Start();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet) const;
  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
  bool IsStarted() const;

  const std::string& LatestError() const;

 protected:
  void Run();

 private:
  const int kMaxReconnectionAttempts_ = 35;

  std::thread th_;
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  std::string latest_error_;
  std::atomic<int> reconnection_attempts_;

  fptn::protocol::https::WebsocketClientSPtr ws_;

  fptn::protocol::https::WebsocketClient::Config config_;

  IPv4Address dns_ipv4_;
  IPv6Address dns_ipv6_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::vpn::http
