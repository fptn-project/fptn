/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"

#include <string>
#include <utility>

#include <boost/asio/executor_work_guard.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::protocol::connection::strategies {

BaseStrategyConnection::BaseStrategyConnection(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config,
    int thread_number)
    : ioc_(thread_number),
      jwt_access_token_(std::move(jwt_access_token)),
      config_(std::move(config)) {}  // NOLINT

BaseStrategyConnection::~BaseStrategyConnection() {
  // Stop io_context
  try {
    if (!ioc_.stopped()) {
      SPDLOG_INFO("Stopping io_context...");
      ioc_.stop();
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }
}

const https::ConnectionConfig& BaseStrategyConnection::Config() const {
  return config_;
}

const std::string& BaseStrategyConnection::JWTAccessToken() const {
  return jwt_access_token_;
}

boost::asio::io_context& BaseStrategyConnection::GetIOContext() { return ioc_; }

bool BaseStrategyConnection::RunningStatus() const { return running_; }

void BaseStrategyConnection::SetRunningStatus(const bool value) {
  running_ = value;
}

void BaseStrategyConnection::RunEventLoop() {
  try {
    // Without the guard run_one() would return before the first async
    // operation is posted. The loop re-checks running_ after every handler, so
    // a missed StopEventLoop() cannot park the thread forever while the
    // connection is still producing events.
    auto guard = boost::asio::make_work_guard(ioc_);
    while (running_) {
      ioc_.run_one();
    }
  } catch (...) {
    SPDLOG_WARN("Exception while running");
  }
  StopEventLoop();
}

void BaseStrategyConnection::StopEventLoop() {
  try {
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }
}

}  // namespace fptn::protocol::connection::strategies
