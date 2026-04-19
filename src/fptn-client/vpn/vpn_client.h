/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include <openssl/base.h>  // NOLINT(build/include_order)
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "http/client.h"
#include "plugins/split/tunneling.h"

namespace fptn::vpn {
class VpnClient final {
 public:
  explicit VpnClient(fptn::vpn::http::ClientPtr http_client,
      fptn::common::network::TunInterfacePtr virtual_net_interface,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      fptn::plugin::PluginList plugins,
      std::size_t thread_pool_size = 4);
  ~VpnClient();
  bool Start();
  bool Stop();
  std::size_t GetSendRate();
  std::size_t GetReceiveRate();
  bool IsStarted();
  [[nodiscard]] std::string GetInterfaceName() const;

 protected:
  void HandlePacketFromVirtualNetworkInterface(
      fptn::common::network::IPPacketPtr packet);
  void HandlePacketFromWebSocket(fptn::common::network::IPPacketPtr packet);

  void ProcessWebSocketPackets();

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  fptn::vpn::http::ClientPtr http_client_;
  fptn::common::network::TunInterfacePtr virtual_net_interface_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;

  const fptn::plugin::PluginList plugins_;

  const std::size_t thread_pool_size_;
  std::vector<std::thread> worker_threads_;
  std::condition_variable ws_queue_cv_;
  std::queue<fptn::common::network::IPPacketPtr> ws_packet_queue_;
};

using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
}  // namespace fptn::vpn
