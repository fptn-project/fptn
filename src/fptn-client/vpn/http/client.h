/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/connection/connection_manager/connection_manager.h"
#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::vpn::http {

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

// Thin adapter over ConnectionManager: keeps the historical Client API used by
// the desktop CLI/GUI while delegating auth, DNS, connect and reconnect logic
// (and its logging) to the unified ConnectionManager.
class Client final {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  using OnIPAssignedCallback =
      std::function<void(const IPv4Address& ip_v4, const IPv6Address& ip_v6)>;

 public:
  explicit Client(fptn::protocol::https::ConnectionConfig config,
      fptn::protocol::connection::strategies::ConnectionStrategy strategy =
          fptn::protocol::connection::strategies::ConnectionStrategy::
              kPersistentTunnel);
  ~Client();
  void SetAccessToken(const std::string& token);
  bool Login(const std::string& username,
      const std::string& password,
      int timeout_sec = 10);
  std::pair<IPv4Address, IPv6Address> GetDns();
  bool Start();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet) const;
  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
  bool IsStarted() const;
  bool IsConnected() const;

  const std::string& LatestError() const;

 private:
  fptn::protocol::connection::ConnectionManager manager_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::vpn::http
