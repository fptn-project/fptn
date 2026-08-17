/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include "filter/manager.h"
#include "nat/table.h"
#include "network/virtual_interface.h"
#include "web/server.h"

namespace fptn::vpn {
class Manager final {
 public:
  struct Config {
    fptn::web::ServerPtr web_server;
    fptn::network::VirtualInterfacePtr network_interface;
    fptn::nat::TableSPtr nat;
    fptn::filter::ManagerSPtr from_client_filter;
    fptn::filter::ManagerSPtr to_client_filter;
    fptn::statistic::MetricsSPtr prometheus;
    std::size_t thread_pool_size = 1;
  };

 public:
  explicit Manager(Config config);
  ~Manager();
  bool Stop();
  bool Start();

 protected:
  void RunToClient() const;
  void RunFromClient() const;
  void RunCollectStatistics();
  void RunUpdateConnectionsStatus();

 private:
  std::atomic<bool> running_ = false;

  Config config_;

  std::vector<std::thread> read_to_client_threads_;
  std::vector<std::thread> read_from_client_threads_;
  std::thread collect_statistics_;
  std::thread connections_status_updater_;
};

using UserManagerSPtr = std::shared_ptr<fptn::user::UserManager>;
}  // namespace fptn::vpn
