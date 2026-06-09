/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "common/client_id.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "nat/table.h"

namespace fptn::web {
namespace http {
using request = boost::beast::http::request<boost::beast::http::string_body>;
using response = boost::beast::http::response<boost::beast::http::string_body>;
}  // namespace http

using ApiHandle = std::function<boost::asio::awaitable<int>(
    const http::request&, http::response&)>;

using ApiHandleMap = std::unordered_map<std::string, ApiHandle>;

inline std::string GetApiKey(
    const std::string& url, const std::string& method) {
  return method + " " + url;
}

inline void AddApiHandle(ApiHandleMap& m,
    const std::string& url,
    const std::string& method,
    const ApiHandle& handle) noexcept {
  const std::string key = GetApiKey(url, method);
  m[key] = handle;
}

inline ApiHandle GetApiHandle(const ApiHandleMap& m,
    const std::string& url,
    const std::string& method) noexcept {
  const std::string key = GetApiKey(url, method);
  const auto& it = m.find(key);
  if (it != m.end()) {
    return it->second;
  }
  return nullptr;
}

class Session;

using WebSocketOpenConnectionCallback = std::function<fptn::client::SessionSPtr(
  fptn::ClientID client_id,
  const fptn::common::network::IPv4Address& client_ip,
  const fptn::common::network::IPv4Address& client_vpn_ipv4,
  const fptn::common::network::IPv6Address& client_vpn_ipv6,
  const std::shared_ptr<Session>& session,
  const std::string& url,
  const std::string& access_token)>;

using WebSocketNewIPPacketCallback = std::function<void(
  fptn::common::network::IPPacketPtr packet)>;

using WebSocketCloseConnectionCallback = std::function<void(
  fptn::ClientID client_id)>;

}  // namespace fptn::web
