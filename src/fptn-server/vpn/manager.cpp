/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/manager.h"

#include <unordered_map>
#include <utility>

using fptn::vpn::Manager;

Manager::Manager(Config config) : config_(std::move(config)) {
  read_to_client_threads_.reserve(config_.thread_pool_size);
  read_from_client_threads_.reserve(config_.thread_pool_size);
}

Manager::~Manager() { Stop(); }

bool Manager::Stop() {
  running_ = false;

  config_.network_interface->Stop();
  config_.web_server->Stop();

  for (auto& thread : read_to_client_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  read_to_client_threads_.clear();

  for (auto& thread : read_from_client_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  read_from_client_threads_.clear();

  if (collect_statistics_.joinable()) {
    collect_statistics_.join();
  }

  if (connections_status_updater_.joinable()) {
    connections_status_updater_.join();
  }
  return true;
}

bool Manager::Start() {
  running_ = true;
  config_.web_server->Start();
  config_.network_interface->Start();

  for (std::size_t i = 0; i < config_.thread_pool_size; ++i) {
    read_to_client_threads_.emplace_back(&Manager::RunToClient, this);
  }

  for (std::size_t i = 0; i < config_.thread_pool_size; ++i) {
    read_from_client_threads_.emplace_back(&Manager::RunFromClient, this);
  }

  collect_statistics_ = std::thread(&Manager::RunCollectStatistics, this);
  connections_status_updater_ =
      std::thread(&Manager::RunUpdateConnectionsStatus, this);
  return collect_statistics_.joinable() &&
         connections_status_updater_.joinable();
}

void Manager::RunToClient() const {
  constexpr std::chrono::milliseconds kTimeout{10};

  std::unordered_map<fptn::ClientID, common::network::BatchIPPacketPtr> batches;

  while (running_) {
    auto packets = config_.network_interface->WaitForPackets(kTimeout, 256);

    for (auto& packet : packets) {
      if (!packet || (!packet->IsIPv4() && !packet->IsIPv6())) {
        continue;
      }

      fptn::nat::ConnectionMultiplexerSPtr nat_session = nullptr;
      if (packet->IsIPv4()) {
        nat_session =
            config_.nat->GetMultiplexerByFakeIPv4(packet->GetDstIPv4Address());
      } else if (packet->IsIPv6()) {
        nat_session =
            config_.nat->GetMultiplexerByFakeIPv6(packet->GetDstIPv6Address());
      }

      if (!nat_session) {
        continue;
      }

      auto& shaper = nat_session->TrafficShaperToClient();
      if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
        continue;
      }

      auto [moved_packet, client_id] =
          nat_session->NextReceiverClientId(std::move(packet));
      packet = std::move(moved_packet);
      if (!client_id) {
        continue;
      }

      packet =
          nat_session->ChangeIPAddressToClientIP(std::move(packet), *client_id);
      if (!packet) {
        continue;
      }

      // filter
      packet = config_.to_client_filter->Apply(
          std::move(packet), fptn::filter::Direction::kToClient);
      if (!packet) {
        continue;
      }

      batches[*client_id].push_back(std::move(packet));
    }
    for (auto& [client_id, batch] : batches) {
      auto web_session = config_.web_server->GetSessionById(client_id);
      if (web_session) {
        web_session->SendBatch(std::move(batch));
      }
    }

    batches.clear();
  }
}

void Manager::RunFromClient() const {
  constexpr std::chrono::milliseconds kTimeout{100};
  while (running_) {
    auto packets = config_.web_server->WaitForPackets(kTimeout);

    if (packets.empty()) {
      continue;
    }

    common::network::BatchIPPacketPtr prepared_batch;
    prepared_batch.reserve(packets.size());

    for (auto& packet : packets) {
      if (!packet || (!packet->IsIPv4() && !packet->IsIPv6())) {
        continue;
      }

      // get session
      const auto session =
          config_.nat->GetMultiplexerByClientId(packet->ClientId());
      if (!session) {
        continue;
      }

      // shaper
      auto shaper = session->TrafficShaperFromClient();
      if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
        continue;
      }

      // filter
      packet = config_.from_client_filter->Apply(
          std::move(packet), fptn::filter::Direction::kFromClient);

      if (packet) {
        packet = session->ChangeIPAddressToFakeIP(std::move(packet));
        if (packet) {
          prepared_batch.emplace_back(std::move(packet));
        }
      }
    }

    if (!prepared_batch.empty() && running_) {
      config_.network_interface->SendBatch(std::move(prepared_batch));
    }
  }
}

void Manager::RunCollectStatistics() {
  constexpr std::chrono::milliseconds kTimeout{300};
  constexpr std::chrono::seconds kCollectInterval{2};

  std::chrono::steady_clock::time_point last_collection_time;
  while (running_) {
    const auto now = std::chrono::steady_clock::now();
    if (now - last_collection_time > kCollectInterval) {
      config_.nat->UpdateStatistic(config_.prometheus);
      last_collection_time = now;
    }
    std::this_thread::sleep_for(kTimeout);
  }
}

void Manager::RunUpdateConnectionsStatus() {
  constexpr std::chrono::milliseconds kInterval{1000};
  while (running_) {
    const auto expired = config_.nat->UpdateConnectionsStatus();
    for (const auto client_id : expired) {
      if (const auto session = config_.web_server->GetSessionById(client_id)) {
        session->Close();  // triggers the close callback -> NAT/table cleanup
      }
    }
    std::this_thread::sleep_for(kInterval);
  }
}
