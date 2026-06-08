/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/http/client.h"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <boost/process/v1/io.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/network/ip_address.h"

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
#include "routing/route_manager.h"

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;
using fptn::protocol::https::ApiClient;
using fptn::vpn::http::Client;

Client::Client(fptn::protocol::https::WebsocketClient::Config config)
    : running_(false),
      reconnection_attempts_(kMaxReconnectionAttempts_),
      config_(std::move(config)) {
  config_.access_token = "";
}

Client::~Client() { Stop(); }

void Client::SetAccessToken(const std::string& token) {
  config_.access_token = token;
}

bool Client::Login(
    const std::string& username, const std::string& password, int timeout_sec) {
  if (!config_.access_token.empty()) {
    return true;
  }

  const std::string request = fmt::format(
      R"({{ "username": "{}", "password": "{}" }})", username, password);

  const std::string ip = config_.server_ip.ToString();
  ApiClient cli(ip, config_.server_port, config_.sni,
      config_.expected_md5_fingerprint, config_.censorship_strategy);

  constexpr int kMaxRetries = 3;
  for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
    if (attempt > 0) {
      SPDLOG_WARN("Login retry attempt {}/{}", attempt, kMaxRetries);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto resp = cli.Post(
        common::api::kApiLoginUrl, request, "application/json", timeout_sec);
    if (resp.code == 200) {
      try {
        const auto msg = resp.Json();
        if (!msg.contains("access_token")) {
          SPDLOG_ERROR(
              "Error: Access token not found in the response. Check your "
              "conection");
        } else {
          config_.access_token = msg["access_token"];
          SPDLOG_INFO("Login successful");
          return true;
        }
      } catch (const nlohmann::json::parse_error& e) {
        config_.access_token = "";
        latest_error_ = e.what();
        SPDLOG_ERROR("Error parsing JSON response: {} ", e.what());
      } catch (const std::exception& ex) {
        config_.access_token = "";
        latest_error_ = ex.what();
        SPDLOG_ERROR("Exception: {}", ex.what());
      }
    } else if (resp.code == 401 || resp.code == 403) {
      config_.access_token = "";
      latest_error_ = resp.errmsg;
      SPDLOG_ERROR("Auth error ({}): wrong username or password", resp.code);
      return false;
    } else {
      config_.access_token = "";
      latest_error_ = resp.errmsg;
      SPDLOG_ERROR(
          "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
    }
  }
  return false;
}

std::pair<IPv4Address, IPv6Address> Client::GetDns() {
  SPDLOG_INFO("Obtained DNS server address. Connecting to {}:{}",
      config_.server_ip.ToString(), config_.server_port);

  if (!dns_ipv4_.IsEmpty() && !dns_ipv6_.IsEmpty()) {
    return {dns_ipv4_, dns_ipv6_};
  }

  const std::string ip = config_.server_ip.ToString();
  ApiClient cli(ip, config_.server_port, config_.sni,
      config_.expected_md5_fingerprint, config_.censorship_strategy);

  constexpr int kMaxRetries = 3;
  for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
    if (attempt > 0) {
      SPDLOG_WARN("GetDns retry attempt {}/{}", attempt, kMaxRetries);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto resp = cli.Get(common::api::kApiDnsUrl);
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

void Client::SetRecvIPPacketCallback(
    const NewIPPacketCallback& callback) noexcept {
  config_.new_ip_pkt_callback = callback;
}

bool Client::Send(fptn::common::network::IPPacketPtr packet) const {
  try {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (ws_ && running_) {
      ws_->Send(std::move(packet));
      return true;
    }
  } catch (const std::runtime_error& err) {
    SPDLOG_ERROR("Send error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred: {}", e.what());
  }
  return false;
}

void Client::Run() {
  // Time window for counting attempts (1 minute)
  constexpr auto kReconnectionWindow = std::chrono::seconds(120);
  // Delay between reconnection attempts
  constexpr auto kReconnectionDelay = std::chrono::milliseconds(300);

  // Current count of reconnection attempts
  reconnection_attempts_ = kMaxReconnectionAttempts_;
  auto window_start_time = std::chrono::steady_clock::now();

  while (running_ && reconnection_attempts_ > 0) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress identicalInnerCondition
      if (running_) {  // Double-check after acquiring lock
        ws_ = std::make_shared<fptn::protocol::https::WebsocketClient>(config_);
      }
    }

    if (running_ && ws_) {
      ws_->Run();  // Start the WebSocket client
    }

    if (!running_) {
      break;
    }

    // clean
    if (ws_) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress knownConditionTrueFalse
      if (ws_ && running_) {
        ws_->Stop();
        ws_.reset();
      }
    }

    // Calculate time since last window start
    const auto current_time = std::chrono::steady_clock::now();
    const auto elapsed = current_time - window_start_time;

    // Reconnection attempt counting logic
    if (elapsed >= kReconnectionWindow) {
      // Reset counter if we're past the time window
      SPDLOG_INFO("Reconnection window reset. New attempt window started");
      reconnection_attempts_ = kMaxReconnectionAttempts_;
      window_start_time = current_time;
    }
    if (reconnection_attempts_ > 0) {
      --reconnection_attempts_;
    }
    // Log connection failure and wait before retrying
    SPDLOG_ERROR(
        "Connection closed (attempt {}/{} in current window). Reconnecting in "
        "{}ms...",
        kMaxReconnectionAttempts_ - reconnection_attempts_,
        kMaxReconnectionAttempts_, kReconnectionDelay.count());

    std::this_thread::sleep_for(kReconnectionDelay);
  }

  if (running_ && !reconnection_attempts_) {
    SPDLOG_ERROR("Connection failure: Could not establish connection");
  }
}

bool Client::Start() {
  running_ = true;
  th_ = std::thread(&Client::Run, this);
  return th_.joinable();
}

bool Client::Stop() {
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

  if (ws_) {
    ws_->Stop();
  }

  if (th_.joinable()) {
    try {
      th_.join();
    } catch (...) {
      SPDLOG_WARN("Unexpected exception during thread join");
    }
  }

  ws_.reset();
  return true;
}

bool Client::IsStarted() const {
  return running_ && reconnection_attempts_ > 0;
}

const std::string& Client::LatestError() const { return latest_error_; }
