#pragma once

/*
 * The FPTN-specific half of multi-server support: probes servers, logs in,
 * and swaps the live tunnel. The policy that decides WHEN to do that lives in
 * failover.h and knows nothing about FPTN.
 */

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config/config_file.h"
#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-vless/failover.h"
#include "fptn-vless/tunnels.h"
#include "vpn/vpn_manager.h"

namespace fptn::vless {

class TunnelManager final : public ITunnels {
 public:
  struct Options {
    std::string sni;
    fptn::protocol::https::CensorshipStrategy censorship_strategy;
    fptn::protocol::connection::strategies::ConnectionStrategy
        connection_strategy;
    int mtu_size = 1420;
    int probe_timeout_sec = 8;
  };

  TunnelManager(const fptn::config::ConfigFile& config, Options options);
  ~TunnelManager() override;
  TunnelManager(const TunnelManager&) = delete;
  TunnelManager& operator=(const TunnelManager&) = delete;

  [[nodiscard]] const std::vector<fptn::utils::speed_estimator::ServerInfo>&
  Servers() const noexcept {
    return servers_;
  }

  // Response time of every server (all at once). Uses the same unauthenticated
  // 100 KB test download FPTN uses to rank servers, through the configured
  // bypass method, so a blocked server shows up as "no response". It does not
  // log in, so it cannot disturb the current session.
  std::vector<PingMs> ProbeAll() override;

  // Makes server `index` the active one. The new connection is logged in
  // first; only then the old tunnel is replaced. False = the old tunnel is
  // left untouched.
  bool Connect(std::size_t index) override;

  // The live tunnel lost its connection (or there is none).
  [[nodiscard]] bool IsDown() const override;

  void Shutdown() override;

  std::vector<std::string> Names() const override;

 private:
  const std::vector<fptn::utils::speed_estimator::ServerInfo> servers_;
  const std::string default_username_;
  const std::string default_password_;
  const Options options_;

  mutable std::mutex mu_;
  std::unique_ptr<fptn::vpn::VpnManager> vpn_;
};

}  // namespace fptn::vless
