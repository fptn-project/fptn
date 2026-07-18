/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>

#include "common/client_id.h"
#include "common/network/ip_address.h"

namespace fptn::nat {

struct ConnectParams {
  ClientID client_id = MAX_CLIENT_ID;

  struct Request {
    std::string url;

    std::string jwt_auth_token;
    std::string session_id;

    std::uint64_t connection_weight = 1;

    std::uint64_t send_duration_ms = 0;
    std::uint64_t ttl_ms = 0;

    fptn::common::network::IPv4Address client_ipv4;
    fptn::common::network::IPv4Address client_tun_vpn_ipv4;
    fptn::common::network::IPv6Address client_tun_vpn_ipv6;
  } request;

  struct User {
    std::string username;
    std::size_t bandwidth_bites_seconds = 0;
  } user;

  bool Validate() const {
    return client_id != MAX_CLIENT_ID && !request.client_ipv4.IsEmpty() &&
           !request.client_tun_vpn_ipv4.IsEmpty() &&
           !request.client_tun_vpn_ipv6.IsEmpty() &&
           !request.jwt_auth_token.empty() && !request.session_id.empty();
  }
};

}  // namespace fptn::nat
