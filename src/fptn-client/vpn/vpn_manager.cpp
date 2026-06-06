/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/vpn_manager.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::vpn {
VpnManager::VpnManager(Config config)
    : running_(false), config_(std::move(config)) {}  // NOLINT

VpnManager::~VpnManager() { Stop(); }

bool VpnManager::IsStarted() {
  if (!running_) {
    return false;
  }

  // const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && config_.http_client && config_.http_client->IsStarted();
}

bool VpnManager::Start() {
  if (running_) {
    return false;
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (running_) {
      return false;
    }
  }
  running_ = true;

  // NOLINTNEXTLINE(modernize-avoid-bind)
  config_.http_client->SetRecvIPPacketCallback(std::bind(
      &VpnManager::HandleOnPacketFromWebSocket, this, std::placeholders::_1));

  bool tun_opened = false;
  if (config_.virtual_net_interface) {
    config_.virtual_net_interface->SetRecvIPPacketCallback(
        // NOLINTNEXTLINE(modernize-avoid-bind)
        std::bind(&VpnManager::HandleOnPacketFromVirtualNetworkInterface, this,
            std::placeholders::_1));
    constexpr int kMaxTunOpenAttempts = 5;
    constexpr auto kTunOpenRetryDelay = std::chrono::milliseconds(100);
    for (int attempt = 1;
        running_ && !tun_opened && attempt <= kMaxTunOpenAttempts; ++attempt) {
      tun_opened = config_.virtual_net_interface->Start();
      if (!tun_opened) {
        SPDLOG_WARN(
            "Failed to open TUN device on (re)connect (attempt {}/{}), "
            "retrying in {} ms",
            attempt, kMaxTunOpenAttempts, kTunOpenRetryDelay.count());
        std::this_thread::sleep_for(kTunOpenRetryDelay);
      }
    }
  }

  if (!tun_opened) {
    SPDLOG_ERROR(
        "Could not open TUN device after IP assignment; skipping route"
        "setup and marking the connection as down so it can recover");
    return false;
  }

  if (config_.route_manager) {
    config_.route_manager->Apply(config_.virtual_net_interface->Name());
  }

  config_.http_client->Start();

  // Start worker
  thread_ = std::thread(&VpnManager::ProcessWebSocketPackets, this);

  return true;
}

bool VpnManager::Stop() {
  if (!running_) {
    return false;
  }
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {
      return false;
    }

    running_ = false;
  }

  ws_queue_cv_.notify_all();

  SPDLOG_INFO("Stopping VPN Websocket-workers...");
  if (thread_.joinable()) {
    thread_.join();
  }

  SPDLOG_INFO("Stopping tasks");
  for (auto& task : pending_tasks_) {
    if (task.valid()) {
      task.wait();
    }
  }
  pending_tasks_.clear();

  SPDLOG_INFO("Stopping VPN client...");

  if (config_.virtual_net_interface) {
    SPDLOG_INFO("Stopping virtual network interface");
    config_.virtual_net_interface->Stop();
    config_.virtual_net_interface.reset();
  }

  if (config_.http_client) {
    SPDLOG_INFO("Stopping HTTP client");
    config_.http_client->Stop();
    config_.http_client.reset();
  }

  return true;
}

std::size_t VpnManager::GetSendRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && config_.virtual_net_interface) {
    return config_.virtual_net_interface->GetSendRate();
  }
  return 0;
}

std::size_t VpnManager::GetReceiveRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && config_.virtual_net_interface) {
    return config_.virtual_net_interface->GetReceiveRate();
  }
  return 0;
}

std::string VpnManager::GetInterfaceName() const {
  if (config_.virtual_net_interface) {
    return config_.virtual_net_interface->Name();
  }
  return {};
}

void VpnManager::HandleOnPacketFromVirtualNetworkInterface(
    fptn::common::network::IPPacketPtr packet) {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && config_.http_client) {
    config_.http_client->Send(std::move(packet));
  }
}

void VpnManager::HandleOnPacketFromWebSocket(
    fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !packet) {
    return;
  }

  constexpr std::size_t kMaxQueueSize = 512;

  std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (ws_packet_queue_.size() >= kMaxQueueSize) {
    SPDLOG_WARN("WebSocket packet queue is full, dropping packet");
    return;
  }

  ws_packet_queue_.push(std::move(packet));
  lock.unlock();
  ws_queue_cv_.notify_one();
}

void VpnManager::ProcessWebSocketPackets() {
  fptn::common::network::IPPacketPtr packet;
  while (running_) {
    {
      std::unique_lock<std::mutex> lock(mutex_);  // mutex

      ws_queue_cv_.wait(
          lock, [this]() { return !ws_packet_queue_.empty() || !running_; });
      if (!running_ && ws_packet_queue_.empty()) {
        break;
      }
      if (!ws_packet_queue_.empty()) {
        packet = std::move(ws_packet_queue_.front());
        ws_packet_queue_.pop();
      }
    }

    if (!packet) {
      continue;
    }

    for (const auto& plugin : config_.plugins) {
      if (packet) {
        auto [processed_packet, triggered] =
            plugin->HandlePacket(std::move(packet));
        packet = std::move(processed_packet);
        if (triggered) {
          break;
        }
      }
    }

    if (packet) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex
      // cppcheck-suppress knownConditionTrueFalse
      if (running_ && config_.virtual_net_interface) {
        config_.virtual_net_interface->Send(std::move(packet));
      }
    }
  }
}

}  // namespace fptn::vpn
