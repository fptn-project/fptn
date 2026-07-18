/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/http/client.h"

#include <string>
#include <utility>

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;
using fptn::vpn::http::Client;

Client::Client(fptn::protocol::https::ConnectionConfig config,
    fptn::protocol::connection::strategies::ConnectionStrategy strategy)
    : manager_(strategy, std::move(config)) {}

Client::~Client() { Stop(); }

void Client::SetAccessToken(const std::string& token) {
  manager_.SetAccessToken(token);
}

bool Client::Login(
    const std::string& username, const std::string& password, int timeout_sec) {
  return manager_.Login(username, password, timeout_sec);
}

std::pair<IPv4Address, IPv6Address> Client::GetDns() {
  return manager_.GetDns();
}

void Client::SetRecvIPPacketCallback(
    const NewIPPacketCallback& callback) noexcept {
  manager_.SetRecvIPPacketCallback(callback);
}

bool Client::Send(fptn::common::network::IPPacketPtr packet) const {
  return manager_.Send(std::move(packet));
}

bool Client::Start() { return manager_.Start(); }

bool Client::Stop() { return manager_.Stop(); }

bool Client::IsStarted() const { return manager_.IsStarted(); }

bool Client::IsConnected() const { return manager_.IsConnected(); }

const std::string& Client::LatestError() const {
  return manager_.LatestError();
}
