/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "config/server_config.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace {
bool ParseBoolean(std::string value) noexcept {
  try {
    // С++17
    // NOLINTNEXTLINE(modernize-use-ranges)
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return value == "true";
  } catch (...) {
    return false;
  }
}
}  // namespace

namespace fptn::config {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

ServerConfig::ServerConfig(int argc, char* argv[])
    : argc_(argc), argv_(argv), args_("fptn-server", FPTN_VERSION) {
  // Required arguments
  args_.add_argument("--server-crt").required().help("Path to server.crt file");
  args_.add_argument("--server-key").required().help("Path to server.key file");
  args_.add_argument("--out-network-interface")
      .required()
      .help("Network out interface");
  // Optional arguments
  args_.add_argument("--server-port")
      .default_value(443)
      .help("Port number")
      .scan<'i', int>();
  args_.add_argument("--mtu-size")
      .default_value(FPTN_DEFAULT_MTU_SIZE)
      .help("MTU size")
      .scan<'i', int>();
  args_.add_argument("--tun-interface-name")
      .default_value("tun0")
      .help("Network interface name");
  /* IPv4 */
  args_.add_argument("--tun-interface-ip")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP4)
      .help("IP address of the virtual interface");
  args_.add_argument("--tun-interface-network-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4)
      .help("IP network of the virtual interface");
  args_.add_argument("--tun-interface-network-mask")
      .default_value(16)
      .help("Network mask")
      .scan<'i', int>();
  /* IPv6 */
  args_.add_argument("--tun-interface-ipv6")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP6)
      .help("IPv6 address of the virtual interface");
  args_.add_argument("--tun-interface-network-ipv6-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6)
      .help("IPv6 network address of the virtual interface");
  args_.add_argument("--tun-interface-network-ipv6-mask")
      .default_value(64)
      .help("IPv6 network mask")
      .scan<'i', int>();
  args_.add_argument("--userfile")
      .help("Path to users file (default: /etc/fptn/users.list)")
      .default_value("/etc/fptn/users.list");
  // Packet filters
  args_.add_argument("--domain-blacklist-file")
      .help(
          "Path to a file with domains to block, one per line ('#' starts a "
          "comment). On a DNS response for a listed domain or any of its "
          "subdomains the answer is rewritten to loopback (127.0.0.1 / ::1). "
          "Empty (default) disables the feature.")
      .default_value("");
  args_.add_argument("--disable-bittorrent")
      .help(
          "Disable BitTorrent traffic filtering. Use this flag to disable "
          "filtering.")
      .default_value("false");
  // Allow prometheus metric
  args_.add_argument("--prometheus-access-key")
      .help(
          "Secret key required for accessing Prometheus metrics. Set this to a "
          "secret value if metrics is needed.")
      .default_value("");
  // Remote server auth
  args_.add_argument("--use-remote-server-auth")
      .help(
          "Enable remote server authentication. Set to 'true' to use a remote "
          "server for authentication.")
      .default_value("false");
  args_.add_argument("--remote-server-auth-host")
      .help(
          "Specify the remote server's IP address or hostname for "
          "authentication.")
      .default_value("1.1.1.1");
  args_.add_argument("--remote-server-auth-port")
      .help(
          "Specify the port number for the remote server authentication. Set "
          "to 0 to use the default port.")
      .default_value(443)
      .scan<'i', int>();
  args_.add_argument("--max-active-sessions-per-user")
      .help("Maximum number of active sessions allowed per VPN user")
      .default_value(3)
      .scan<'i', int>();
  // Probing
  args_.add_argument("--enable-detect-probing")
      .help(
          "Enable detection of non-FPTN clients or probing attempts during SSL "
          "handshake. ")
      .default_value("false");
  args_.add_argument("--default-proxy-domain")
      .help("Default domain for proxying non-VPN clients.")
      .default_value(FPTN_DEFAULT_SNI);
  args_.add_argument("--allowed-sni-list")
      .help(
          "Comma-separated list of allowed SNI hostnames for non-VPN clients.\n"
          "Behavior logic:\n"
          " - List is empty (default): proxy all non-VPN traffic to "
          "--default-proxy-domain\n"
          " - List is NOT empty: use as whitelist:\n"
          "   - Client SNI in list -> proxy to client's SNI\n"
          "   - Client SNI not in list -> proxy to --default-proxy-domain")
      .default_value("");
  // Prevent self-proxy
  args_.add_argument("--server-external-ips")
      .help(
          "Public IPv4 address of this VPN server. "
          "Prevents proxy loops when clients connect via IP. "
          "Example: --server-external-ip 1.2.3.4,5.6.7.8")
      .default_value("");
}

bool ServerConfig::Parse() noexcept {  // NOLINT(bugprone-exception-escape)
  try {
    args_.parse_args(argc_, argv_);
    return true;
  } catch (const std::runtime_error& err) {
    const std::string help = args_.help().str();
    SPDLOG_ERROR("Argument parsing error: {}\n{}", err.what(), help);
  } catch (...) {
    SPDLOG_ERROR("Undefined parser error");
  }
  return false;
}

std::string ServerConfig::ServerCrt() const {
  return args_.get<std::string>("--server-crt");
}

std::string ServerConfig::ServerKey() const {
  return args_.get<std::string>("--server-key");
}

std::string ServerConfig::OutNetworkInterface() const {
  return args_.get<std::string>("--out-network-interface");
}

int ServerConfig::ServerPort() const { return args_.get<int>("--server-port"); }

std::string ServerConfig::TunInterfaceName() const {
  return args_.get<std::string>("--tun-interface-name");
}

IPv4Address ServerConfig::TunInterfaceIPv4() const {
  return IPv4Address(args_.get<std::string>("--tun-interface-ip"));
}

IPv4Address ServerConfig::TunInterfaceNetworkIPv4Address() const {
  return IPv4Address(args_.get<std::string>("--tun-interface-network-address"));
}

std::uint32_t ServerConfig::TunInterfaceNetworkIPv4Mask() const {
  const int value = args_.get<int>("--tun-interface-network-mask");
  return static_cast<std::uint32_t>(value);
}

IPv6Address ServerConfig::TunInterfaceIPv6() const {
  return IPv6Address(args_.get<std::string>("--tun-interface-ipv6"));
}

IPv6Address ServerConfig::TunInterfaceNetworkIPv6Address() const {
  return IPv6Address(
      args_.get<std::string>("--tun-interface-network-ipv6-address"));
}

std::uint32_t ServerConfig::TunInterfaceNetworkIPv6Mask() const {
  const int value = args_.get<int>("--tun-interface-network-ipv6-mask");
  return static_cast<std::uint32_t>(value);
}

std::string ServerConfig::UserFile() const {
  return args_.get<std::string>("--userfile");
}

bool ServerConfig::DisableBittorrent() const {
  return ParseBoolean(args_.get<std::string>("--disable-bittorrent"));
}

std::string ServerConfig::DomainBlacklistFile() const {
  return args_.get<std::string>("--domain-blacklist-file");
}

std::string ServerConfig::PrometheusAccessKey() const {
  return args_.get<std::string>("--prometheus-access-key");
}

bool ServerConfig::UseRemoteServerAuth() const {
  return ParseBoolean(args_.get<std::string>("--use-remote-server-auth"));
}

std::string ServerConfig::RemoteServerAuthHost() const {
  return args_.get<std::string>("--remote-server-auth-host");
}

int ServerConfig::RemoteServerAuthPort() const {
  return args_.get<int>("--remote-server-auth-port");
}

bool ServerConfig::EnableDetectProbing() const {
  return ParseBoolean(args_.get<std::string>("--enable-detect-probing"));
}

[[nodiscard]]
std::string ServerConfig::DefaultProxyDomain() const {
  auto default_domain = args_.get<std::string>("--default-proxy-domain");
  if (default_domain.empty()) {
    return FPTN_DEFAULT_SNI;
  }
  return default_domain;
}

[[nodiscard]]
std::vector<std::string> ServerConfig::AllowedSniList() const {
  const auto allowed_sni = args_.get<std::string>("--allowed-sni-list");
  if (!allowed_sni.empty()) {
    return common::utils::SplitCommaSeparated(
        allowed_sni + "," + DefaultProxyDomain());
  }
  return {};
}

std::size_t ServerConfig::MaxActiveSessionsPerUser() const {
  return static_cast<std::size_t>(
      args_.get<int>("--max-active-sessions-per-user"));
}

[[nodiscard]]
std::string ServerConfig::ServerExternalIPs() const {
  return args_.get<std::string>("--server-external-ips");
}

[[nodiscard]]
int ServerConfig::MtuSize() const {
  return args_.get<int>("--mtu-size");
}

}  // namespace fptn::config
