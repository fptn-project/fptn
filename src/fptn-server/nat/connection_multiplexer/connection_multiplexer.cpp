/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/connection_multiplexer/connection_multiplexer.h"

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

namespace fptn::nat {

namespace {
bool HasClientId(
    const ClientConnectionPtr& connection, fptn::ClientID client_id) {
  return connection->Params().client_id == client_id;
}

bool Contains(const std::vector<ClientConnectionPtr>& connections,
    fptn::ClientID client_id) {
  return std::ranges::any_of(
      connections, [client_id](const ClientConnectionPtr& connection) {
        return HasClientId(connection, client_id);
      });
}

bool Remove(
    std::vector<ClientConnectionPtr>& connections, fptn::ClientID client_id) {
  const auto it = std::ranges::find_if(
      connections, [client_id](const ClientConnectionPtr& connection) {
        return HasClientId(connection, client_id);
      });
  if (it == connections.end()) {
    return false;
  }
  connections.erase(it);
  return true;
}

ClientConnectionPtr FindByClientId(
    const std::vector<ClientConnectionPtr>& connections,
    fptn::ClientID client_id) {
  const auto it = std::ranges::find_if(
      connections, [client_id](const ClientConnectionPtr& connection) {
        return HasClientId(connection, client_id);
      });
  return it != connections.end() ? *it : nullptr;
}

// Adds a connection to each bucket its current role qualifies it for; a
// bidirectional connection goes into both.
void PlaceByRole(std::vector<ClientConnectionPtr>& sending,
    std::vector<ClientConnectionPtr>& receiving,
    const ClientConnectionPtr& connection) {
  if (connection->IsSending()) {
    sending.push_back(connection);
  }
  if (connection->IsReceiving()) {
    receiving.push_back(connection);
  }
}
}  // namespace

ConnectionMultiplexer::ConnectionMultiplexer(const ConnectParams& params,
    IPv4Address fake_client_ipv4,
    IPv6Address fake_client_ipv6,
    fptn::traffic_shaper::LeakyBucketSPtr to_client,
    fptn::traffic_shaper::LeakyBucketSPtr from_client)
    : username_(params.user.username),
      session_id_(params.request.session_id),
      fake_client_ipv4_(std::move(fake_client_ipv4)),
      fake_client_ipv6_(std::move(fake_client_ipv6)),
      shaper_to_client_(std::move(to_client)),
      shaper_from_client_(std::move(from_client)),
      disable_checksum_calculation_(false) {
  PlaceByRole(sending_, receiving_, ClientConnection::Create(params));
}

bool ConnectionMultiplexer::AddClientConnection(const ConnectParams& params) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  if (Contains(sending_, params.client_id) ||
      Contains(receiving_, params.client_id)) {
    return false;
  }
  PlaceByRole(sending_, receiving_, ClientConnection::Create(params));
  return true;
}

bool ConnectionMultiplexer::HasClientId(fptn::ClientID client_id) const {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  return Contains(sending_, client_id) || Contains(receiving_, client_id);
}

bool ConnectionMultiplexer::DelConnectionByClientId(fptn::ClientID client_id) {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  // A bidirectional connection lives in both buckets, so remove it from each.
  const bool from_sending = Remove(sending_, client_id);
  const bool from_receiving = Remove(receiving_, client_id);
  return from_sending || from_receiving;
}

bool ConnectionMultiplexer::Empty() const {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  return sending_.empty() && receiving_.empty();
}

std::vector<fptn::ClientID> ConnectionMultiplexer::UpdateConnectionsStatus() {
  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  std::vector<ClientConnectionPtr> connections = std::move(sending_);
  for (auto& connection : receiving_) {
    if (!Contains(connections, connection->Params().client_id)) {
      connections.push_back(std::move(connection));
    }
  }
  sending_.clear();
  receiving_.clear();

  std::vector<fptn::ClientID> expired;
  for (const auto& connection : connections) {
    if (connection->IsExpired()) {
      expired.push_back(connection->Params().client_id);
      continue;
    }
    PlaceByRole(sending_, receiving_, connection);
  }
  return expired;
}

std::pair<fptn::common::network::IPPacketPtr, std::optional<fptn::ClientID>>
ConnectionMultiplexer::NextReceiverClientId(
    fptn::common::network::IPPacketPtr packet) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  if (receiving_.empty() || !packet) {
    return {std::move(packet), std::nullopt};
  }
  std::size_t start = 0;
  if (packet->IsTCP()) {
    start = packet->GetTcpDstPort();
  } else if (packet->IsUDP()) {
    start = packet->GetUdpDstPort();
  } else {
    start = round_robin_cursor_.fetch_add(1, std::memory_order_relaxed);
  }
  const std::size_t index = start % receiving_.size();
  return {std::move(packet), receiving_[index]->Params().client_id};
}

fptn::common::network::IPPacketPtr
ConnectionMultiplexer::ChangeIPAddressToClientIP(
    fptn::common::network::IPPacketPtr packet,
    fptn::ClientID client_id) const noexcept {
  packet->SetClientId(client_id);

  if (disable_checksum_calculation_) {
    return packet;
  }

  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  ClientConnectionPtr connection = FindByClientId(receiving_, client_id);
  if (connection == nullptr) {
    return nullptr;
  }
  const auto& request = connection->Params().request;
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(request.client_tun_vpn_ipv4);
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(request.client_tun_vpn_ipv6);
  }
  packet->ComputeCalculateFields();
  return packet;
}

fptn::common::network::IPPacketPtr
ConnectionMultiplexer::ChangeIPAddressToFakeIP(
    fptn::common::network::IPPacketPtr packet) const noexcept {
  if (disable_checksum_calculation_) {
    return packet;
  }

  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_);
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_);
  }
  packet->ComputeCalculateFields();
  return packet;
}

void ConnectionMultiplexer::DisableChecksumCalculation(
    const bool value) noexcept {
  disable_checksum_calculation_ = value;
}

const std::string& ConnectionMultiplexer::UserName() const noexcept {
  return username_;
}

const std::string& ConnectionMultiplexer::SessionId() const noexcept {
  return session_id_;
}

const IPv4Address& ConnectionMultiplexer::FakeClientIPv4() const noexcept {
  return fake_client_ipv4_;
}

const IPv6Address& ConnectionMultiplexer::FakeClientIPv6() const noexcept {
  return fake_client_ipv6_;
}

fptn::traffic_shaper::LeakyBucketSPtr&
ConnectionMultiplexer::TrafficShaperToClient() noexcept {
  return shaper_to_client_;
}

fptn::traffic_shaper::LeakyBucketSPtr&
ConnectionMultiplexer::TrafficShaperFromClient() noexcept {
  return shaper_from_client_;
}

}  // namespace fptn::nat
