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

#include "fptn-protocol-lib/time/time_provider.h"

namespace {
std::chrono::seconds ReconnectBackoff(int full_restart_count) {
  switch (full_restart_count) {
    case 1:
      return std::chrono::seconds(2);
    case 2:
      return std::chrono::seconds(5);
    case 3:
      return std::chrono::seconds(15);
    default:
      return std::chrono::seconds(30);
  }
}
}  // namespace

namespace fptn::vpn {
VpnManager::VpnManager(Config config)
    : running_(false),
      ever_connected_(false),
      gave_up_(false),
      reconnecting_(false),
      reconnect_attempt_(0),
      config_(std::move(config)) {}  // NOLINT

VpnManager::~VpnManager() { Stop(); }

bool VpnManager::IsStarted() {
  if (!running_) {
    return false;
  }

  // const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (gave_up_) {
    return false;
  }
  if (ever_connected_) {
    return true;
  }
  return config_.http_client && config_.http_client->IsStarted();
}

bool VpnManager::IsReconnecting() const { return reconnecting_; }

int VpnManager::ReconnectAttempt() const { return reconnect_attempt_; }

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int VpnManager::MaxReconnectAttempts() const { return kMaxFullRestarts_; }

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

  supervisor_thread_ = std::thread(&VpnManager::Supervise, this);

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
  reconnect_cv_.notify_all();

  if (supervisor_thread_.joinable()) {
    supervisor_thread_.join();
  }

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

  constexpr std::size_t kMaxQueueSize = 1024 * 16;

  std::unique_lock<std::mutex> lock(queue_mutex_);

  if (ws_packet_queue_.size() >= kMaxQueueSize) {
    SPDLOG_WARN("WebSocket packet queue is full, dropping packet");
    return;
  }

  ws_packet_queue_.push(std::move(packet));
  lock.unlock();
  ws_queue_cv_.notify_one();
}

void VpnManager::ProcessWebSocketPackets() {
  while (running_) {
    fptn::common::network::BatchIPPacketPtr batch;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex
      ws_queue_cv_.wait(
          lock, [this]() { return !ws_packet_queue_.empty() || !running_; });
      if (!running_ && ws_packet_queue_.empty()) {
        break;
      }
      while (!ws_packet_queue_.empty()) {
        batch.push_back(std::move(ws_packet_queue_.front()));
        ws_packet_queue_.pop();
      }
    }

    if (batch.empty()) {
      continue;
    }

    fptn::common::network::BatchIPPacketPtr to_send;
    to_send.reserve(batch.size());
    for (auto& packet : batch) {
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
        to_send.push_back(std::move(packet));
      }
    }

    if (!to_send.empty()) {
      const std::unique_lock<std::mutex> lock(mutex_);
      // cppcheck-suppress knownConditionTrueFalse
      if (running_ && config_.virtual_net_interface) {
        for (auto& packet : to_send) {
          config_.virtual_net_interface->Send(std::move(packet));
        }
      }
    }
  }
}

void VpnManager::Supervise() {
  int full_restart_count = 0;
  while (running_) {
    {
      std::unique_lock<std::mutex> lock(reconnect_mutex_);
      reconnect_cv_.wait_for(lock, std::chrono::milliseconds(500),
          [this]() { return !running_ || !config_.http_client->IsStarted(); });
    }
    if (!running_) {
      break;
    }
    if (config_.http_client->IsConnected()) {
      ever_connected_ = true;
      full_restart_count = 0;
      reconnecting_ = false;
      reconnect_attempt_ = 0;
      continue;
    }
    if (ever_connected_) {
      reconnecting_ = true;
    }
    if (config_.http_client->IsStarted()) {
      continue;
    }

    if (full_restart_count >= kMaxFullRestarts_) {
      SPDLOG_ERROR("VPN reconnection failed after {} full restarts. Giving up.",
          kMaxFullRestarts_);
      config_.route_manager->Clean();
      reconnecting_ = false;
      gave_up_ = true;
      break;
    }
    ++full_restart_count;
    reconnect_attempt_ = full_restart_count;
    SPDLOG_WARN(
        "Full VPN restart {}/{}", full_restart_count, kMaxFullRestarts_);

    config_.http_client->Stop();
    config_.route_manager->Clean();
    fptn::time::TimeProvider::Instance()->SyncWithNtp();

    {
      std::unique_lock<std::mutex> lock(reconnect_mutex_);
      reconnect_cv_.wait_for(lock, ReconnectBackoff(full_restart_count),
          [this]() { return !running_.load(); });
    }
    if (!running_) {
      break;
    }

    config_.route_manager->Apply(config_.virtual_net_interface->Name());
    config_.http_client->Start();
  }
}

}  // namespace fptn::vpn
