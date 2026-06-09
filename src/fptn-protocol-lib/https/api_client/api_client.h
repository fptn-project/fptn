/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <nlohmann/json.hpp>

#include "fptn-protocol-lib/https/censorship_strategy.h"

namespace fptn::protocol::https {

struct Response final {
  std::string body;
  int code;
  std::string errmsg;

  Response() : code(600) {}

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  Response(const Response& other)
      : body(other.body), code(other.code), errmsg(other.errmsg) {}

  Response& operator=(const Response& other) {
    if (this != &other) {
      this->~Response();
      new (this) Response(other);
    }
    return *this;
  }

  Response(Response&& other) = default;
  Response& operator=(Response&& other) = default;

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

class ApiClient {
 public:
  ApiClient(const std::string& host,
      int port,
      CensorshipStrategy censorship_strategy);

  ApiClient(std::string host,
      int port,
      std::string sni,
      CensorshipStrategy censorship_strategy);

  ApiClient(std::string host,
      int port,
      std::string sni,
      std::string md5_fingerprint,
      CensorshipStrategy censorship_strategy);

  Response Get(const std::string& handle, int timeout = 5) const;
  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type = "application/json",
      int timeout = 5) const;
  boost::asio::awaitable<Response> AsyncPost(const std::string& handle,
      const std::string& request,
      const std::string& content_type = "application/json",
      int timeout = 5) const;
  bool TestHandshake(int timeout = 5) const;

 protected:
  ApiClient Clone() const;

  Response GetImpl(const std::string& handle, int timeout) const;

  Response PostImpl(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout) const;

  bool TestHandshakeImpl(int timeout) const;

  bool PerformFakeHandshake2(boost::asio::ip::tcp::socket& socket) const;

  bool onVerifyCertificate(
      const std::string& md5_fingerprint, std::string& error) const;

  std::vector<std::uint8_t> GenerateHandshakePacket() const;

 private:
  const std::string host_;
  const int port_;
  const std::string sni_;
  const std::string expected_md5_fingerprint_;
  const CensorshipStrategy censorship_strategy_;
};

using HttpsClientPtr = std::unique_ptr<ApiClient>;

}  // namespace fptn::protocol::https
