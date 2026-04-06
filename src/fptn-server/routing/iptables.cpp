/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/iptables.h"

#ifdef __linux__
#include <cerrno>
#include <cstring>
#include <sys/resource.h>  // NOLINT(build/include_order)
#endif

#include <string>
#include <utility>
#include <vector>

#include <boost/process.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/io.hpp>
#include <boost/process/v1/search_path.hpp>
#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::routing::RouteManager;

namespace {
bool RunCommand(const std::string& command) noexcept {
  try {
    boost::process::v1::child child(command,
        boost::process::v1::std_out > stdout,
        boost::process::v1::std_err > stderr);
    child.wait();
    if (child.exit_code() == 0) {
      return true;
    }
  } catch (const std::exception& e) {
    SPDLOG_WARN("IPTables warning: {}", e.what());
  } catch (...) {
    SPDLOG_WARN("Undefined warning");
  }
  return false;
}

#ifdef __linux__
bool SetMaxFileDescriptors() {
  struct rlimit current_limits = {};
  if (getrlimit(RLIMIT_NOFILE, &current_limits) != 0) {
    SPDLOG_WARN(
        "Failed to get current file descriptor limits: {}", strerror(errno));
    return false;
  }

  SPDLOG_INFO("Current file descriptor limits: soft={}, hard={}",
      current_limits.rlim_cur, current_limits.rlim_max);

  struct rlimit new_limits = {};
  new_limits.rlim_cur = current_limits.rlim_max;
  new_limits.rlim_max = current_limits.rlim_max;

  // Try to set the new limits
  if (setrlimit(RLIMIT_NOFILE, &new_limits) != 0) {
    SPDLOG_WARN("Failed to set file descriptor limits: {}", strerror(errno));
    return false;
  }

  // Verify the changes were applied
  struct rlimit verified_limits;
  if (getrlimit(RLIMIT_NOFILE, &verified_limits) != 0) {
    SPDLOG_WARN(
        "Failed to verify new file descriptor limits: {}", strerror(errno));
    return false;
  }

  SPDLOG_INFO("New file descriptor limits: soft={}, hard={}",
      verified_limits.rlim_cur, verified_limits.rlim_max);
  return true;
}
#endif

}  // namespace

RouteManager::RouteManager(
    std::string out_net_interface_name, std::string tun_net_interface_name)
    : out_net_interface_name_(std::move(out_net_interface_name)),
      tun_net_interface_name_(std::move(tun_net_interface_name)),
      running_(false) {}

RouteManager::~RouteManager() {
  try {
    Clean();
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Exception in IPTables destructor: {}", ex.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown error in IPTables destructor");
  }
}

bool RouteManager::Apply() {  // NOLINT(bugprone-exception-escape)
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

#ifdef __linux__
  SetMaxFileDescriptors();
#endif

  running_ = true;
#ifdef __linux__
  const std::vector<std::string> commands = {"systemctl start sysctl",
      "sysctl -w net.ipv4.ip_forward=1",
      "sysctl -w net.ipv4.conf.all.rp_filter=0",
      "sysctl -w net.ipv4.conf.default.rp_filter=0",
      "sysctl -w net.ipv6.conf.default.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.all.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.lo.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.all.forwarding=1", "sysctl -p",
      /* IPv4 */
      "iptables -P INPUT ACCEPT", "iptables -P FORWARD ACCEPT",
      "iptables -P OUTPUT ACCEPT",
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_),
      /* IPv6 */
      "ip6tables -P INPUT ACCEPT", "ip6tables -P FORWARD ACCEPT",
      "ip6tables -P OUTPUT ACCEPT",
      fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("ip6tables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_)};
#elif __APPLE__
  // NEED CHECK
  const std::vector<std::string> commands = {
      fmt::format("echo 'set skip on lo0' > /tmp/pf.conf"),
      fmt::format("echo 'block in all' >> /tmp/pf.conf"),
      fmt::format("echo 'pass out all' >> /tmp/pf.conf"),
      fmt::format("echo 'block in on {} from any to any' >> /tmp/pf.conf",
          out_net_interface_name_),
      "pfctl -ef /tmp/pf.conf",
  };
#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      if (!RunCommand(cmd)) {
        SPDLOG_WARN("COMMAND ERROR: {}", cmd);
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred while applying routing: {}", e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred while applying routing.");
    return false;
  }
  return true;
}

// NOLINT(bugprone-exception-escape)
bool RouteManager::Clean() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (!running_) {
    return true;
  }
#ifdef __linux__
  const std::vector<std::string> commands = {
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_)};
#elif __APPLE__
  const std::vector<std::string> commands = {
      "echo 'set skip on lo0' > /tmp/pf.conf",
      "echo 'block in all' >> /tmp/pf.conf",
      "echo 'pass out all' >> /tmp/pf.conf",
      fmt::format("echo 'pass in on {} from any to any' >> /tmp/pf.conf",
          out_net_interface_name_),
      fmt::format("echo 'pass in on {} from {} to any' >> /tmp/pf.conf",
          tun_net_interface_name_, tun_net_interface_name_),
      "pfctl -f /tmp/pf.conf", "pfctl -e"};
#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      RunCommand(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  running_ = false;
  return true;
}
