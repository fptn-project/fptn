/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/table.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::nat {
Table::Table(Config config)
    : config_(std::move(config)),
      ipv4_generator_(config_.tun_ipv4_network, config_.tun_network_ipv4_mask),
      ipv6_generator_(config_.tun_ipv6_network, config_.tun_network_ipv6_mask) {
  const std::uint32_t ipv4_available = ipv4_generator_.NumAvailableAddresses();
  const auto ipv6_available = ipv6_generator_.NumAvailableAddresses();
  const std::uint32_t capacity = (ipv6_available > ipv4_available)
      ? ipv4_available
      : static_cast<std::uint32_t>(ipv6_available);
  free_ipv4_.reserve(capacity);
  free_ipv6_.reserve(capacity);
  for (std::uint32_t i = 0; i < capacity; ++i) {
    const auto ip = ipv4_generator_.GetNextAddress();
    if (ip != config_.tun_ipv4) {
      free_ipv4_.push_back(ip);
    }
  }
  for (std::uint32_t i = 0; i < capacity; ++i) {
    const auto ip = ipv6_generator_.GetNextAddress();
    if (ip != config_.tun_ipv6) {
      free_ipv6_.push_back(ip);
    }
  }
}

fptn::client::SessionSPtr Table::CreateClientSession(ClientID client_id,
    const std::string& user_name,
    const fptn::common::network::IPv4Address& client_ipv4,
    const fptn::common::network::IPv6Address& client_ipv6,
    const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
    const fptn::traffic_shaper::LeakyBucketSPtr& from_client) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  if (!client_id_to_sessions_.contains(client_id)) {
    if (free_ipv4_.empty() || free_ipv6_.empty()) {
      SPDLOG_INFO("Client limit was exceeded");
      return nullptr;
    }
    const auto fake_ipv4 = free_ipv4_.back();
    free_ipv4_.pop_back();
    const auto fake_ipv6 = free_ipv6_.back();
    free_ipv6_.pop_back();
    try {
      auto session = std::make_shared<fptn::client::Session>(
          fptn::client::Session::Config{.client_id = client_id,
              .user_name = user_name,
              .client_ipv4 = client_ipv4,
              .fake_client_ipv4 = fake_ipv4,
              .client_ipv6 = client_ipv6,
              .fake_client_ipv6 = fake_ipv6,
              .to_client = to_client,
              .from_client = from_client});
      client_id_to_sessions_.insert({client_id, session});
      ipv4_to_sessions_.insert(
          {fake_ipv4.ToInt(), session});  // ipv4 -> session
      ipv6_to_sessions_.insert(
          {fake_ipv6.ToString(), session});  // ipv6 -> session
      return session;
    } catch (const std::runtime_error& err) {
      SPDLOG_INFO("Client error: {}", err.what());
    } catch (const std::exception& e) {
      SPDLOG_ERROR(
          "Standard exception while creating client session: {}", e.what());
    } catch (...) {
      SPDLOG_ERROR("An unknown error occurred while creating client session.");
    }
    free_ipv4_.push_back(fake_ipv4);
    free_ipv6_.push_back(fake_ipv6);
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::CreateClientSession2(ClientID client_id,
    const std::string& user_name,
    const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
    const fptn::traffic_shaper::LeakyBucketSPtr& from_client) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  if (!client_id_to_sessions_.contains(client_id)) {
    if (free_ipv4_.empty() || free_ipv6_.empty()) {
      SPDLOG_INFO("Client limit was exceeded");
      return nullptr;
    }
    const auto fake_ipv4 = free_ipv4_.back();
    free_ipv4_.pop_back();

    const auto fake_ipv6 = free_ipv6_.back();
    free_ipv6_.pop_back();

    try {
      auto session = std::make_shared<fptn::client::Session>(
          fptn::client::Session::Config{.client_id = client_id,
              .user_name = user_name,
              .client_ipv4 = fake_ipv4,
              .fake_client_ipv4 = fake_ipv4,
              .client_ipv6 = fake_ipv6,
              .fake_client_ipv6 = fake_ipv6,
              .to_client = to_client,
              .from_client = from_client});

      client_id_to_sessions_.insert({client_id, session});
      ipv4_to_sessions_.insert(
          {fake_ipv4.ToInt(), session});  // ipv4 -> session
      ipv6_to_sessions_.insert(
          {fake_ipv6.ToString(), session});  // ipv6 -> session
      return session;
    } catch (const std::runtime_error& err) {
      SPDLOG_INFO("Client error: {}", err.what());
    } catch (const std::exception& e) {
      SPDLOG_ERROR(
          "Standard exception while creating client session: {}", e.what());
    } catch (...) {
      SPDLOG_ERROR("An unknown error occurred while creating client session.");
    }
    free_ipv4_.push_back(fake_ipv4);
    free_ipv6_.push_back(fake_ipv6);
  }
  return nullptr;
}

bool Table::DelClientSession(ClientID client_id) {
  fptn::client::SessionSPtr ipv4_session;
  fptn::client::SessionSPtr ipv6_session;
  {
    const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

    auto it = client_id_to_sessions_.find(client_id);
    if (it != client_id_to_sessions_.end()) {
      const auto& fake_ipv4 = it->second->FakeClientIPv4();
      const auto& fake_ipv6 = it->second->FakeClientIPv6();
      free_ipv4_.push_back(fake_ipv4);
      free_ipv6_.push_back(fake_ipv6);

      // delete ipv4 -> session
      {
        auto it_ipv4 = ipv4_to_sessions_.find(fake_ipv4.ToInt());
        if (it_ipv4 != ipv4_to_sessions_.end()) {
          ipv4_session = std::move(it_ipv4->second);
          ipv4_to_sessions_.erase(it_ipv4);
        }
      }
      // delete ipv6 -> session
      {
        auto it_ipv6 = ipv6_to_sessions_.find(fake_ipv6.ToString());
        if (it_ipv6 != ipv6_to_sessions_.end()) {
          ipv6_session = std::move(it_ipv6->second);
          ipv6_to_sessions_.erase(it_ipv6);
        }
      }
      client_id_to_sessions_.erase(it);
    }
  }
  return ipv4_session != nullptr && ipv6_session != nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv4(
    const fptn::common::network::IPv4Address& ip) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = ipv4_to_sessions_.find(ip.ToInt());
  if (it != ipv4_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv6(
    const fptn::common::network::IPv6Address& ip) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  auto it = ipv6_to_sessions_.find(ip.ToString());
  if (it != ipv6_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByClientId(
    ClientID clientId) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  auto it = client_id_to_sessions_.find(clientId);
  if (it != client_id_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

std::size_t Table::GetNumberActiveSessionByUsername(
    const std::string& username) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  return std::ranges::count_if(
      ipv4_to_sessions_, [&username](const auto& pair) {
        return pair.second->UserName() == username;
      });
}

void Table::UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  prometheus->UpdateActiveSessions(client_id_to_sessions_.size());
  for (const auto& client : client_id_to_sessions_) {
    auto client_id = client.first;
    const auto& session = client.second;
    prometheus->UpdateStatistics(client_id, session->UserName(),
        session->TrafficShaperToClient()->FullDataAmount(),
        session->TrafficShaperFromClient()->FullDataAmount());
  }
}
}  // namespace fptn::nat
