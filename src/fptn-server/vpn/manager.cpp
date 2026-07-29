/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/manager.h"

#include <unordered_map>
#include <utility>

using fptn::vpn::Manager;

Manager::Manager(fptn::web::ServerPtr web_server,
    fptn::network::VirtualInterfacePtr network_interface,
    fptn::nat::TableSPtr nat,
    fptn::filter::ManagerSPtr filter,
    fptn::statistic::MetricsSPtr prometheus,
    std::size_t thread_pool_size)
    : web_server_(std::move(web_server)),
      network_interface_(std::move(network_interface)),
      nat_(std::move(nat)),
      filter_(std::move(filter)),
      prometheus_(std::move(prometheus)),
      thread_pool_size_(thread_pool_size > 0 ? thread_pool_size : 1) {
  read_to_client_threads_.reserve(thread_pool_size_);
  read_from_client_threads_.reserve(thread_pool_size_);
}

Manager::~Manager() { Stop(); }

bool Manager::Stop() {
  running_ = false;

  network_interface_->Stop();
  web_server_->Stop();

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
  web_server_->Start();
  network_interface_->Start();

  for (std::size_t i = 0; i < thread_pool_size_; ++i) {
    read_to_client_threads_.emplace_back(&Manager::RunToClient, this);
  }

  for (std::size_t i = 0; i < thread_pool_size_; ++i) {
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
    auto packets = network_interface_->WaitForPackets(kTimeout, 256);

    for (auto& packet : packets) {
      if (!packet || (!packet->IsIPv4() && !packet->IsIPv6())) {
        continue;
      }

      fptn::nat::ConnectionMultiplexerSPtr nat_session = nullptr;
      if (packet->IsIPv4()) {
        nat_session =
            nat_->GetMultiplexerByFakeIPv4(packet->GetDstIPv4Address());
      } else if (packet->IsIPv6()) {
        nat_session =
            nat_->GetMultiplexerByFakeIPv6(packet->GetDstIPv6Address());
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

      packet = nat_session->ChangeIPAddressToClientIP(
          std::move(packet), *client_id);
      if (!packet) {
        continue;
      }

      batches[*client_id].push_back(std::move(packet));
    }
    for (auto& [client_id, batch] : batches) {
      auto web_session = web_server_->GetSessionById(client_id);
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
    auto packets = web_server_->WaitForPackets(kTimeout);

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
      const auto session = nat_->GetMultiplexerByClientId(packet->ClientId());
      if (!session) {
        continue;
      }

      // shaper
      auto shaper = session->TrafficShaperFromClient();
      if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
        continue;
      }

      // filter
      packet = filter_->Apply(std::move(packet));

      if (packet) {
        packet = session->ChangeIPAddressToFakeIP(std::move(packet));
        if (packet) {
          prepared_batch.emplace_back(std::move(packet));
        }
      }
    }

    if (!prepared_batch.empty() && running_) {
      network_interface_->SendBatch(std::move(prepared_batch));
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
      nat_->UpdateStatistic(prometheus_);
      last_collection_time = now;
    }
    std::this_thread::sleep_for(kTimeout);
  }
}

void Manager::RunUpdateConnectionsStatus() {
  constexpr std::chrono::milliseconds kInterval{1000};
  while (running_) {
    const auto expired = nat_->UpdateConnectionsStatus();
    for (const auto client_id : expired) {
      if (const auto session = web_server_->GetSessionById(client_id)) {
        session->Close();  // triggers the close callback -> NAT/table cleanup
      }
    }
    std::this_thread::sleep_for(kInterval);
  }
}
