/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/connection_manager/connection_manager.h"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <boost/process/v1/io.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/connection/strategies/browser_mimicry/browser_mimicry.h"
#include "fptn-protocol-lib/connection/strategies/rolling_tunnel/rolling_tunnel.h"
#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::protocol::connection {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;
using fptn::protocol::https::ApiClient;

ConnectionManager::ConnectionManager(
    strategies::ConnectionStrategy connection_strategy_type,
    fptn::protocol::https::ConnectionConfig config)
    : running_(false),
      reconnection_attempts_(0),
      connection_strategy_type_(connection_strategy_type),
      config_(std::move(config)) {}  // NOLINT

ConnectionManager::~ConnectionManager() {
  if (strategy_connection_) {
    strategy_connection_->Stop();
    strategy_connection_.reset();
  }
}

void ConnectionManager::SetRecvIPPacketCallback(
    const fptn::protocol::https::OnIPRecvPacketCallback& callback) {
  config_.common.recv_ip_packet_callback = callback;
}

void ConnectionManager::SetRecvBatchIPPacketCallback(
    const fptn::protocol::https::OnIPRecvBatchPacketCallback& callback) {
  config_.common.recv_ip_packet_batch_callback = callback;
}

void ConnectionManager::SetAccessToken(const std::string& token) {
  jwt_access_token_ = token;
}

bool ConnectionManager::Login(
    const std::string& username, const std::string& password, int timeout_sec) {
  if (!jwt_access_token_.empty()) {
    return true;
  }

  const std::string request = fmt::format(
      R"({{ "username": "{}", "password": "{}" }})", username, password);

  const std::string ip = config_.common.server_ip.ToString();
  ApiClient cli(ip, config_.common.server_port, config_.common.sni,
      config_.common.md5_fingerprint, config_.common.censorship_strategy);

  constexpr int kMaxRetries = 3;
  for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
    if (attempt > 0) {
      SPDLOG_WARN("Login retry attempt {}/{}", attempt, kMaxRetries);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto resp =
        cli.Post("/api/v1/login", request, "application/json", timeout_sec);
    if (resp.code == 200) {
      try {
        const auto msg = resp.Json();
        if (!msg.contains("access_token")) {
          SPDLOG_ERROR(
              "Error: Access token not found in the response. Check your "
              "conection");
        } else {
          jwt_access_token_ = msg["access_token"];
          SPDLOG_INFO("Login successful");
          return true;
        }
      } catch (const nlohmann::json::parse_error& e) {
        jwt_access_token_ = "";
        latest_error_ = e.what();
        SPDLOG_ERROR("Error parsing JSON response: {} ", e.what());
      } catch (const std::exception& ex) {
        jwt_access_token_ = "";
        latest_error_ = ex.what();
        SPDLOG_ERROR("Exception: {}", ex.what());
      }
    } else if (resp.code == 401 || resp.code == 403) {
      jwt_access_token_ = "";
      latest_error_ = resp.errmsg;
      SPDLOG_ERROR("Auth error ({}): wrong username or password", resp.code);
      return false;
    } else {
      jwt_access_token_ = "";
      latest_error_ = resp.errmsg;
      SPDLOG_ERROR(
          "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
    }
  }
  return false;
}

std::pair<IPv4Address, IPv6Address> ConnectionManager::GetDns() {
  SPDLOG_INFO("Obtained DNS server address. Connecting to {}:{}",
      config_.common.server_ip.ToString(), config_.common.server_port);

  if (!dns_ipv4_.IsEmpty() && !dns_ipv6_.IsEmpty()) {
    return {dns_ipv4_, dns_ipv6_};
  }

  const std::string ip = config_.common.server_ip.ToString();
  ApiClient cli(ip, config_.common.server_port, config_.common.sni,
      config_.common.md5_fingerprint, config_.common.censorship_strategy);

  constexpr int kMaxRetries = 3;
  for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
    if (attempt > 0) {
      SPDLOG_WARN("GetDns retry attempt {}/{}", attempt, kMaxRetries);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto resp = cli.Get("/api/v1/dns");
    if (resp.code == 200) {
      try {
        const auto msg = resp.Json();
        if (!msg.contains("dns")) {
          SPDLOG_ERROR(
              "Error: dns not found in the response. Check your connection");
        } else {
          const std::string dns_ipv4 = msg["dns"];
          const std::string dns_ipv6 =
              (msg.contains("dns_ipv6") ? msg["dns_ipv6"]
                                        : FPTN_SERVER_DEFAULT_ADDRESS_IP6);
          dns_ipv4_ = IPv4Address(dns_ipv4);
          dns_ipv6_ = IPv6Address(dns_ipv6);
          return {dns_ipv4_, dns_ipv6_};
        }
      } catch (const nlohmann::json::parse_error& e) {
        latest_error_ = e.what();
        SPDLOG_ERROR("Error parsing JSON response: {}", e.what());
      } catch (const std::exception& ex) {
        latest_error_ = ex.what();
        SPDLOG_ERROR("Exception: {}", ex.what());
      }
    } else {
      latest_error_ = resp.errmsg;
      SPDLOG_ERROR(
          "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
    }
  }
  return {dns_ipv4_, dns_ipv6_};
}

bool ConnectionManager::Start() {
  running_ = true;
  th_ = std::thread(&ConnectionManager::Run, this);
  return th_.joinable();
}

bool ConnectionManager::Stop() {
  if (!running_) {
    return false;
  }

  SPDLOG_INFO("Stopping client");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!running_) {  // Double-check after acquiring lock
      return false;
    }
    running_ = false;
  }

  if (strategy_connection_) {
    strategy_connection_->Stop();
  }

  if (th_.joinable()) {
    try {
      th_.join();
    } catch (...) {
      SPDLOG_WARN("Unexpected exception during thread join");
    }
  }

  strategy_connection_.reset();
  return true;
}

bool ConnectionManager::Send(fptn::common::network::IPPacketPtr packet) const {
  try {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (strategy_connection_ && running_) {
      strategy_connection_->Send(std::move(packet));
      return true;
    }
  } catch (const std::runtime_error& err) {
    SPDLOG_ERROR("Send error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred: {}", e.what());
  }
  return false;
}

bool ConnectionManager::IsStarted() const { return running_; }

bool ConnectionManager::IsConnected() const {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && strategy_connection_ &&
         strategy_connection_->IsConnected();
}

const std::string& ConnectionManager::LatestError() const {
  return latest_error_;
}

void ConnectionManager::Run() {
  // Time window for counting attempts (1 minute)
  constexpr auto kReconnectionWindow = std::chrono::seconds(120);
  // Delay between reconnection attempts
  constexpr auto kReconnectionDelay = std::chrono::milliseconds(300);

  // Current count of reconnection attempts
  reconnection_attempts_ = 0;
  auto window_start_time = std::chrono::steady_clock::now();

  const auto max_reconnection = config_.common.max_reconnections;
  while (running_ && reconnection_attempts_ < max_reconnection) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress identicalInnerCondition
      if (running_ &&
          connection_strategy_type_ ==
              strategies::ConnectionStrategy::kSingleRollingTunnel) {
        strategy_connection_ =
            strategies::SingleRollingTunnel::Create(jwt_access_token_, config_);
      } else if (running_ &&
                 connection_strategy_type_ ==
                     strategies::ConnectionStrategy::kBrowserMimicry) {
        strategy_connection_ =
            strategies::BrowserMimicry::Create(jwt_access_token_, config_);
      } else if (running_ &&
                 connection_strategy_type_ ==
                     strategies::ConnectionStrategy::kDualRollingTunnel) {
        strategy_connection_ =
            strategies::DualRollingTunnel::Create(jwt_access_token_, config_);
      } else if (running_ &&
                 connection_strategy_type_ ==
                     strategies::ConnectionStrategy::kTripleRollingTunnel) {
        strategy_connection_ =
            strategies::TripleRollingTunnel::Create(jwt_access_token_, config_);
      }
    }

    if (running_ && strategy_connection_) {
      strategy_connection_->Start();  // Start the WebSocket client
    }

    if (!running_) {
      break;
    }

    // clean
    if (strategy_connection_) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress knownConditionTrueFalse
      if (strategy_connection_ && running_) {
        strategy_connection_->Stop();
        strategy_connection_.reset();
      }
    }

    // Calculate time since last window start
    const auto current_time = std::chrono::steady_clock::now();
    const auto elapsed = current_time - window_start_time;

    // Reconnection attempt counting logic
    if (elapsed >= kReconnectionWindow) {
      // Reset counter if we're past the time window
      reconnection_attempts_ = 0;
      window_start_time = current_time;
    } else {
      ++reconnection_attempts_;  // Decrement counter if within time window
    }

    // Log connection failure and wait before retrying
    SPDLOG_ERROR(
        "Connection closed (attempt {}/{} in current window). Reconnecting in "
        "{}ms...",
        reconnection_attempts_, max_reconnection, kReconnectionDelay.count());

    std::this_thread::sleep_for(kReconnectionDelay);
  }

  if (running_ && !reconnection_attempts_) {
    SPDLOG_ERROR("Connection failure: Could not establish connection");
  }

  running_ = false;
}

}  // namespace fptn::protocol::connection
