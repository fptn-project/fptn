/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <utility>

namespace fptn::utils::speed_estimator {

struct ServerInfo {
  std::string name;
  std::string host;
  int port;
  bool is_using;
  std::string md5_fingerprint;

  std::string username;
  std::string password;
  std::string service_name;

  // Deployment-wide shared secret S for the keyed TLS session-id marker.
  // Empty keeps the legacy (unkeyed) marker. Carried per-server so it reaches
  // every ApiClient/WebsocketClient the same way md5_fingerprint does; the
  // value itself is service-level (see ConfigFile::Parse).
  std::string session_key;

  ServerInfo() : port(0), is_using(false) {}

  ServerInfo(std::string _name,
      std::string _host,
      int _port,
      std::string _md5_fingerprint)
      : name(std::move(_name)),
        host(std::move(_host)),
        port(_port),
        is_using(false),
        md5_fingerprint(std::move(_md5_fingerprint)) {}
};

}  // namespace fptn::utils::speed_estimator
