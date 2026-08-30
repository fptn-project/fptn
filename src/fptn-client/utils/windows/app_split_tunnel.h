/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#if _WIN32

#include <memory>
#include <string>
#include <vector>

#include "common/network/ip_address.h"

namespace fptn::utils::windows {

// Windows application-based split tunnel backend.
//
// Selected applications are excluded from the VPN tunnel and use the primary
// network interface directly. This backend communicates with the open-source
// Mullvad Windows split-tunnel driver. It is intentionally optional: if the
// driver is missing or cannot be initialized, the VPN itself keeps working.
class AppSplitTunnel final {
 public:
  struct Config {
    std::vector<std::wstring> excluded_app_paths;
    fptn::common::network::IPv4Address vpn_server_ip;
    fptn::common::network::IPv4Address tunnel_ipv4;
    fptn::common::network::IPv6Address tunnel_ipv6;
  };

  explicit AppSplitTunnel(Config config);
  ~AppSplitTunnel();

  AppSplitTunnel(const AppSplitTunnel&) = delete;
  AppSplitTunnel& operator=(const AppSplitTunnel&) = delete;

  bool Start();
  void Stop();
  bool IsStarted() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fptn::utils::windows

#endif  // _WIN32
