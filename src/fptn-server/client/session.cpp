/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "client/session.h"

#include <string>
#include <utility>

namespace fptn::client {

Session::Session(Config config)
    : config_(std::move(config)),
      disable_checksum_calculation_(false) {}  // NOLINT

const fptn::ClientID& Session::ClientId() const noexcept {
  return config_.client_id;
}

const std::string& Session::UserName() const noexcept {
  return config_.user_name;
}

const IPv4Address& Session::ClientIPv4() const noexcept {
  return config_.client_ipv4;
}

const IPv4Address& Session::FakeClientIPv4() const noexcept {
  return config_.fake_client_ipv4;
}

const IPv6Address& Session::ClientIPv6() const noexcept {
  return config_.client_ipv6;
}

const IPv6Address& Session::FakeClientIPv6() const noexcept {
  return config_.fake_client_ipv6;
}

fptn::traffic_shaper::LeakyBucketSPtr&
Session::TrafficShaperToClient() noexcept {
  return config_.to_client;
}

fptn::traffic_shaper::LeakyBucketSPtr&
Session::TrafficShaperFromClient() noexcept {
  return config_.from_client;
}

fptn::common::network::IPPacketPtr Session::ChangeIPAddressToClientIP(
    fptn::common::network::IPPacketPtr packet) const noexcept {
  packet->SetClientId(config_.client_id);

  if (disable_checksum_calculation_) {
    return packet;
  }

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(client_ipv4_.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(client_ipv6_.ToString());
  }
#else
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(config_.client_ipv4);
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(config_.client_ipv6);
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}

fptn::common::network::IPPacketPtr Session::ChangeIPAddressToFakeIP(
    fptn::common::network::IPPacketPtr packet) const noexcept {
  packet->SetClientId(config_.client_id);

  if (disable_checksum_calculation_) {
    return packet;
  }

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_.ToString());
  }
#else
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(config_.fake_client_ipv4);
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(config_.fake_client_ipv6);
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}

void Session::DisableChecksumCalculation(const bool value) noexcept {
  disable_checksum_calculation_ = value;
}
}  // namespace fptn::client
