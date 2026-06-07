/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "common/data/channel.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "routing/route_manager.h"

namespace fptn::network {

class VirtualInterface final {
 public:
  VirtualInterface(const std::string& name,
      int mtu_size,
      fptn::routing::RouteManagerPtr route_manager,
      fptn::common::network::TunInterface::Config config);
  ~VirtualInterface();

  bool Check() const noexcept;
  bool Start() noexcept;
  bool Stop() noexcept;
  void Send(fptn::common::network::IPPacketPtr packet) noexcept;
  void SendBatch(fptn::common::network::BatchIPPacketPtr packets) noexcept;

  common::network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration) noexcept;
  common::network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept;

 protected:
  void IPPacketFromNetwork(fptn::common::network::IPPacketPtr packet) noexcept;

 private:
  std::thread thread_;
  std::atomic<bool> running_;

  const std::string name_;
  const fptn::routing::RouteManagerPtr route_manager_;

  fptn::common::network::TunInterface::Config config_;

  fptn::common::data::Channel from_network_;
  fptn::common::network::TunInterfaceSPtr virtual_network_interface_;
};

using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;
}  // namespace fptn::network
