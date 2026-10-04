#include "fptn-vless/tunnel_manager.h"

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"
#include "fptn-vless/events.h"
#include "common/network/net_interface.h"
#include "fptn-client/utils/speed_estimator/speed_estimator.h"
#include "fptn-protocol-lib/https/connection_config.h"
#include "fptn-vless/userspace_stack.h"
#include "routing/route_manager.h"  // ResolveDomain only
#include "vpn/http/client.h"

namespace fptn::vless {

using fptn::utils::speed_estimator::ServerInfo;

TunnelManager::TunnelManager(
    const fptn::config::ConfigFile& config, Options options)
    : servers_(config.GetServers()),
      default_username_(config.GetUsername()),
      default_password_(config.GetPassword()),
      options_(std::move(options)) {}

TunnelManager::~TunnelManager() { Shutdown(); }

std::vector<PingMs> TunnelManager::ProbeAll() {
  struct State {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<PingMs> results;
    std::size_t done = 0;
  };
  auto state = std::make_shared<State>();
  state->results.resize(servers_.size());

  for (std::size_t i = 0; i < servers_.size(); ++i) {
    // Detached on purpose (like FPTN's own speed estimator): a probe that
    // hangs must not hold up the others, its late answer is simply ignored.
    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::thread([state, i, server = servers_[i], sni = options_.sni,
                    timeout = options_.probe_timeout_sec,
                    strategy = options_.censorship_strategy]() {
      PingMs ping;
      try {
        const std::uint64_t ms = fptn::utils::speed_estimator::GetDownloadTimeMs(
            server, sni, timeout, server.md5_fingerprint, strategy);
        if (ms != UINT64_MAX) {  // GetDownloadTimeMs' "no answer" marker
          ping = static_cast<std::uint32_t>(
              std::min<std::uint64_t>(ms, UINT32_MAX));
        }
      } catch (...) {  // NOLINT
      }
      {
        const std::lock_guard<std::mutex> lock(state->mu);
        state->results[i] = ping;
        ++state->done;
      }
      state->cv.notify_all();
    }).detach();
  }

  std::unique_lock<std::mutex> lock(state->mu);
  state->cv.wait_for(
      lock, std::chrono::seconds(options_.probe_timeout_sec + 2),
      [&state, this]() { return state->done == servers_.size(); });
  return state->results;
}

bool TunnelManager::Connect(std::size_t index) {
  if (index >= servers_.size()) {
    return false;
  }
  const ServerInfo& server = servers_[index];
  try {
    const auto server_ip = fptn::routing::ResolveDomain(server.host);
    if (server_ip.IsEmpty()) {
      SPDLOG_WARN("DNS resolve error: {}", server.host);
      return false;
    }
    const auto tun_ipv4 = fptn::common::network::IPv4Address::Create(
        FPTN_CLIENT_DEFAULT_ADDRESS_IP4);
    const auto tun_ipv6 = fptn::common::network::IPv6Address::Create(
        FPTN_CLIENT_DEFAULT_ADDRESS_IP6);

    // 1. Log in to the NEW server while the old tunnel keeps working.
    auto http_client = std::make_unique<fptn::vpn::http::Client>(
        fptn::protocol::https::ConnectionConfig{
            .common ={
                    .server_ip = server_ip,
                    .server_port = static_cast<std::uint16_t>(server.port),
                    .sni = options_.sni,
                    .md5_fingerprint = server.md5_fingerprint,
                    .client_version = FPTN_VERSION,
                    .censorship_strategy = options_.censorship_strategy,
                    .tun_interface_address_ipv4 = tun_ipv4,
                    .tun_interface_address_ipv6 = tun_ipv6,
                }},
        options_.connection_strategy);
    const std::string& username =
        server.username.empty() ? default_username_ : server.username;
    const std::string& password =
        server.password.empty() ? default_password_ : server.password;
    if (!http_client->Login(username, password)) {
      Notify("Login to '{}' failed (code {}): {}", server.name,
          http_client->LatestErrorCode(), http_client->LatestError());
      return false;
    }
    const auto [dns_ipv4, dns_ipv6] = http_client->GetDns();
    if (dns_ipv4.IsEmpty()) {
      SPDLOG_WARN("Server '{}' did not provide a DNS address", server.name);
      return false;
    }

    // 2. The new one is ready: replace the old tunnel. Two tunnels must never
    // run at once, they would fight over the packets of the userspace stack.
    const std::lock_guard<std::mutex> lock(mu_);
    if (vpn_) {
      vpn_->Stop();
      vpn_.reset();
    }
    // The old server knows nothing about our open connections.
    UserspaceStack::Instance().ResetForNewTunnel(dns_ipv4.ToString());

    auto virtual_network_interface =
        std::make_shared<fptn::common::network::TunInterface>(
            fptn::common::network::TunInterface::Config{
                .name = "fptn-userspace",
                .mtu_size = options_.mtu_size,
                .using_rate_calculator = false,
                .ipv4_addr = tun_ipv4,
                .ipv4_netmask = 32,
                .ipv6_addr = tun_ipv6,
                .ipv6_netmask = 126});
    // No route manager, no plugins: nothing is changed on this machine.
    auto vpn = std::make_unique<fptn::vpn::VpnManager>(
        fptn::vpn::VpnManager::Config{.http_client = std::move(http_client),
            .route_manager = nullptr,
            .virtual_net_interface = virtual_network_interface,
            .plugins = {}});
    if (!vpn->Start()) {
      Notify("Cannot start the FPTN connection to '{}'", server.name);
      return false;  // IsDown() is now true; the controller will move on
    }
    vpn_ = std::move(vpn);
    return true;
  } catch (const std::exception& ex) {
    Notify("Connecting to '{}' failed: {}", server.name, ex.what());
  } catch (...) {
    SPDLOG_WARN("Connecting to '{}' failed", server.name);
  }
  return false;
}

std::vector<std::string> TunnelManager::Names() const {
  std::vector<std::string> names;
  for (const auto& server : servers_) {
    names.push_back(server.name);
  }
  return names;
}

bool TunnelManager::IsDown() const {
  const std::lock_guard<std::mutex> lock(mu_);
  return !vpn_ || vpn_->IsReconnecting() || !vpn_->IsStarted();
}

void TunnelManager::Shutdown() {
  const std::lock_guard<std::mutex> lock(mu_);
  if (vpn_) {
    vpn_->Stop();
    vpn_.reset();
  }
}

}  // namespace fptn::vless
