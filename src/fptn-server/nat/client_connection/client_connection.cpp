/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/client_connection/client_connection.h"

#include <chrono>
#include <utility>

namespace fptn::nat {

namespace {
using Clock = std::chrono::steady_clock;
}  // namespace

ClientConnection::ClientConnection(fptn::nat::ConnectParams params)
    : params_(std::move(params)), accepted_at_(Clock::now()) {}

const fptn::nat::ConnectParams& ClientConnection::Params() const noexcept {
  return params_;
}

bool ClientConnection::IsBidirectional() const noexcept {
  const auto& request = params_.request;
  return request.send_duration_ms == 0 && request.ttl_ms == 0;
}

bool ClientConnection::IsSending() const noexcept {
  if (IsBidirectional()) {
    return true;
  }
  const auto send_until = accepted_at_ + std::chrono::milliseconds(
                                             params_.request.send_duration_ms);
  return Clock::now() < send_until;
}

bool ClientConnection::IsReceiving() const noexcept {
  if (IsBidirectional()) {
    return true;
  }
  const auto send_until = accepted_at_ + std::chrono::milliseconds(
                                             params_.request.send_duration_ms);
  return Clock::now() >= send_until;
}

bool ClientConnection::IsExpired() const noexcept {
  const auto& request = params_.request;
  return request.ttl_ms != 0 &&
         Clock::now() >=
             accepted_at_ + std::chrono::milliseconds(request.ttl_ms);
}

}  // namespace fptn::nat
