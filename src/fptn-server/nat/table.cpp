/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/table.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::nat {

Table::Table(Config config)
    : config_(std::move(config)),
      ipv4_generator_(config_.tun_ipv4_network, config_.tun_network_ipv4_mask),
      ipv6_generator_(config_.tun_ipv6_network, config_.tun_network_ipv6_mask) {
  const std::uint32_t ipv4_available = ipv4_generator_.NumAvailableAddresses();
  const auto ipv6_available = ipv6_generator_.NumAvailableAddresses();
  const std::uint32_t capacity =
      (ipv6_available > ipv4_available)
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

ConnectionMultiplexerSPtr Table::AddConnection(const ConnectParams& params,
    const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
    const fptn::traffic_shaper::LeakyBucketSPtr& from_client) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  // Join an existing logical session (a pool sharing the same session_id).
  if (const auto it = session_to_mplx_.find(params.request.session_id);
      it != session_to_mplx_.end()) {
    auto& mplx = it->second;
    if (mplx->UserName() != params.user.username) {
      SPDLOG_WARN(
          "Session belongs to another user, rejecting client_id={} user='{}'",
          params.client_id, params.user.username);
      return nullptr;
    }
    if (!mplx->AddClientConnection(params)) {
      SPDLOG_WARN("Connection with client_id={} already exists in session",
          params.client_id);
      return nullptr;
    }
    client_to_mplx_.insert({params.client_id, mplx});
    return mplx;
  }

  if (free_ipv4_.empty() || free_ipv6_.empty()) {
    SPDLOG_INFO("Client limit was exceeded");
    return nullptr;
  }
  const auto fake_ipv4 = free_ipv4_.back();
  const auto fake_ipv6 = free_ipv6_.back();

  try {
    auto mplx = ConnectionMultiplexer::Create(
        params, fake_ipv4, fake_ipv6, to_client, from_client);

    free_ipv4_.pop_back();
    free_ipv6_.pop_back();

    session_to_mplx_.insert({params.request.session_id, mplx});
    ipv4_to_mplx_.insert({fake_ipv4.ToInt(), mplx});
    ipv6_to_mplx_.insert({fake_ipv6.ToBytes(), mplx});
    client_to_mplx_.insert({params.client_id, mplx});
    return mplx;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error while creating connection multiplexer: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown error while creating connection multiplexer");
  }
  return nullptr;
}

bool Table::DelConnectionByClientId(ClientID client_id) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = client_to_mplx_.find(client_id);
  if (it == client_to_mplx_.end()) {
    return false;
  }
  auto mplx = it->second;
  client_to_mplx_.erase(it);
  mplx->DelConnectionByClientId(client_id);

  ReleaseSessionIfEmpty(mplx);
  return true;
}

// The logical session is torn down once its last connection is gone.
void Table::ReleaseSessionIfEmpty(const ConnectionMultiplexerSPtr& mplx) {
  if (!mplx->Empty()) {
    return;
  }
  const auto it = session_to_mplx_.find(mplx->SessionId());
  if (it == session_to_mplx_.end() || it->second != mplx) {
    return;  // already released
  }
  const auto& fake_ipv4 = mplx->FakeClientIPv4();
  const auto& fake_ipv6 = mplx->FakeClientIPv6();
  free_ipv4_.push_back(fake_ipv4);
  free_ipv6_.push_back(fake_ipv6);
  ipv4_to_mplx_.erase(fake_ipv4.ToInt());
  ipv6_to_mplx_.erase(fake_ipv6.ToBytes());
  session_to_mplx_.erase(mplx->SessionId());
}

ConnectionMultiplexerSPtr Table::GetMultiplexerByFakeIPv4(
    const fptn::common::network::IPv4Address& ip) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = ipv4_to_mplx_.find(ip.ToInt());
  if (it != ipv4_to_mplx_.end()) {
    return it->second;
  }
  return nullptr;
}

ConnectionMultiplexerSPtr Table::GetMultiplexerByFakeIPv6(
    const fptn::common::network::IPv6Address& ip) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = ipv6_to_mplx_.find(ip.ToBytes());
  if (it != ipv6_to_mplx_.end()) {
    return it->second;
  }
  return nullptr;
}

ConnectionMultiplexerSPtr Table::GetMultiplexerByClientId(
    ClientID client_id) noexcept {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto it = client_to_mplx_.find(client_id);
  if (it != client_to_mplx_.end()) {
    return it->second;
  }
  return nullptr;
}

std::size_t Table::GetNumberActiveSessionByUsername(
    const std::string& username) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  return std::ranges::count_if(session_to_mplx_, [&username](const auto& pair) {
    return pair.second->UserName() == username;
  });
}

std::vector<ClientID> Table::UpdateConnectionsStatus() {
  std::vector<ClientID> expired;
  std::vector<ConnectionMultiplexerSPtr> emptied;
  {
    const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

    for (const auto& mplx : session_to_mplx_ | std::views::values) {
      auto ids = mplx->UpdateConnectionsStatus();
      expired.insert(expired.end(), ids.begin(), ids.end());
      if (mplx->Empty()) {
        emptied.push_back(mplx);
      }
    }
  }
  if (expired.empty() && emptied.empty()) {
    return expired;
  }

  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  for (const auto client_id : expired) {
    client_to_mplx_.erase(client_id);
  }
  for (const auto& mplx : emptied) {
    ReleaseSessionIfEmpty(mplx);
  }
  return expired;
}

void Table::UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  prometheus->UpdateActiveSessions(session_to_mplx_.size());
  for (const auto& mplx : session_to_mplx_ | std::views::values) {
    prometheus->UpdateStatistics(0, mplx->UserName(),
        mplx->TrafficShaperToClient()->FullDataAmount(),
        mplx->TrafficShaperFromClient()->FullDataAmount());
  }
}

}  // namespace fptn::nat
