/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <queue>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "http/client.h"
#include "plugins/split/tunneling.h"

namespace fptn::vpn {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

class VpnManager final {
 public:
  struct Config {
    fptn::vpn::http::ClientPtr http_client;
    fptn::routing::RouteManagerSPtr route_manager;
    fptn::common::network::TunInterfaceSPtr virtual_net_interface;
    fptn::plugin::PluginList plugins;
  };

 public:
  explicit VpnManager(Config config);
  ~VpnManager();

  bool Start();
  bool Stop();
  std::size_t GetSendRate();
  std::size_t GetReceiveRate();
  bool IsStarted();
  [[nodiscard]] std::string GetInterfaceName() const;

 protected:
  void ProcessWebSocketPackets();

  void HandleOnPacketFromVirtualNetworkInterface(
      fptn::common::network::IPPacketPtr packet);
  void HandleOnPacketFromWebSocket(fptn::common::network::IPPacketPtr packet);

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  Config config_;

  std::thread thread_;
  std::condition_variable ws_queue_cv_;
  std::queue<fptn::common::network::IPPacketPtr> ws_packet_queue_;

  std::vector<std::future<void>> pending_tasks_;
};

using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnManager>;
}  // namespace fptn::vpn
