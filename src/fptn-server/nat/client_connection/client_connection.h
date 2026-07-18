/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <utility>

#include "nat/connect_params.h"

namespace fptn::nat {

class ClientConnection final {
 public:
  static std::shared_ptr<ClientConnection> Create(
      fptn::nat::ConnectParams params) {
    return std::make_shared<ClientConnection>(std::move(params));
  }

  explicit ClientConnection(fptn::nat::ConnectParams params);

  const fptn::nat::ConnectParams& Params() const noexcept;

  bool IsSending() const noexcept;
  bool IsReceiving() const noexcept;
  bool IsExpired() const noexcept;

 protected:
  bool IsBidirectional() const noexcept;

 private:
  const fptn::nat::ConnectParams params_;
  const std::chrono::steady_clock::time_point accepted_at_;
};

using ClientConnectionPtr = std::shared_ptr<ClientConnection>;

}  // namespace fptn::nat
