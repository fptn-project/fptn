/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/route_manager.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "common/network/net_interface.h"
#include "common/system/command.h"

namespace {
#ifdef _WIN32
std::string GetWindowsInterfaceNumber(const std::string& interface_name) {
  if (interface_name.empty()) {
    return {};
  }

  ULONG out_buf_len = 15000;
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

  std::unique_ptr<IP_ADAPTER_ADDRESSES[]> adapter_addresses;
  DWORD ret = ERROR_BUFFER_OVERFLOW;

  for (int i = 0; i < 3 && ret == ERROR_BUFFER_OVERFLOW; i++) {
    adapter_addresses = std::make_unique<IP_ADAPTER_ADDRESSES[]>(
        out_buf_len / sizeof(IP_ADAPTER_ADDRESSES) + 1);

    ret = GetAdaptersAddresses(
        AF_UNSPEC, flags, nullptr, adapter_addresses.get(), &out_buf_len);

    if (ret == ERROR_BUFFER_OVERFLOW) {
      adapter_addresses.reset();
    }
  }

  if (ret == NO_ERROR && adapter_addresses) {
    PIP_ADAPTER_ADDRESSES current = adapter_addresses.get();
    DWORD if_index = 0;

    while (current) {
      std::string adapter_name = current->AdapterName;

      int size_need = WideCharToMultiByte(
          CP_UTF8, 0, current->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
      std::string friendly_name(size_need - 1, 0);
      WideCharToMultiByte(CP_UTF8, 0, current->FriendlyName, -1,
          &friendly_name[0], size_need, nullptr, nullptr);

      size_need = WideCharToMultiByte(
          CP_UTF8, 0, current->Description, -1, nullptr, 0, nullptr, nullptr);
      std::string description(size_need - 1, 0);
      WideCharToMultiByte(CP_UTF8, 0, current->Description, -1, &description[0],
          size_need, nullptr, nullptr);

      if (interface_name == adapter_name || interface_name == friendly_name ||
          interface_name == description) {
        if_index = current->IfIndex;
        break;
      }
      current = current->Next;
    }

    return if_index > 0 ? std::to_string(if_index) : std::string();
  }

  return {};
}

std::pair<std::string, std::string> ParseIPv4CIDR(const std::string& network) {
  std::string ip = network;
  std::string mask = "255.255.255.255";

  std::size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 32) {
        std::uint32_t mask_value = 0;
        if (cidr > 0) {
          mask_value = ~0u << (32 - cidr);
        }
        mask = fmt::format("{}.{}.{}.{}", (mask_value >> 24) & 0xFF,
            (mask_value >> 16) & 0xFF, (mask_value >> 8) & 0xFF,
            mask_value & 0xFF);
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse CIDR: {}", network);
    }
  }
  return {ip, mask};
}

std::pair<std::string, int> ParseIPv6CIDR(const std::string& network) {
  std::string ip = network;
  int prefix = 128;

  size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 128) {
        prefix = cidr;
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse IPv6 CIDR: {}", network);
    }
  }
  return {ip, prefix};
}
#elif __linux__

std::vector<std::string> GetLinuxDnsServers(const std::string& interface) {
  std::vector<std::string> dns_servers;

  const std::string command = fmt::format(
      "resolvectl status {} | grep 'DNS Servers:' | awk -F': ' '{{print $2}}'",
      interface);

  std::vector<std::string> output;
  fptn::common::system::command::run(command, output);

  if (!output.empty() && !output[0].empty()) {
    std::istringstream iss(output[0]);
    std::string server;
    while (iss >> server) {
      if (!server.empty()) {
        dns_servers.push_back(server);
      }
    }
  }
  return dns_servers;
}
#endif

bool AddIPv4RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command =
        fmt::format(R"(ip route add {} via "{}" dev "{}" )", destination,
            gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    std::string interface_param = "";
    if (!out_interface.empty()) {
      std::string interface_number = GetWindowsInterfaceNumber(out_interface);
      if (!interface_number.empty()) {
        interface_param = "if " + interface_number;
      }
    }
    const std::string command =
        fmt::format("route add {} mask {} {} METRIC 2 {}", ip, mask, gateway_ip,
            interface_param);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv4 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv4 route: {}", destination);
    return false;
  }
}

bool AddIPv6RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command =
        fmt::format(R"(ip -6 route add {} via "{}" dev "{}" )", destination,
            gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    std::string interface_name = out_interface;
    if (interface_name.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route on Windows");
      return false;
    }
    const std::string command =
        fmt::format("netsh interface ipv6 add route {}/{} \"{}\" {}", ip,
            prefix, interface_name, gateway_ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv6 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv6 route: {}", destination);
    return false;
  }
}

bool RemoveIPv4RouteFromSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip route del {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    std::string interface_param = "";
    if (!out_interface.empty()) {
      std::string interface_number = GetWindowsInterfaceNumber(out_interface);
      if (!interface_number.empty()) {
        interface_param = "if " + interface_number;
      }
    }
    const std::string command = fmt::format(
        "route delete {} mask {} {} {}", ip, mask, gateway_ip, interface_param);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv4 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error removing IPv4 route: {}", destination);
    return false;
  }
}

bool RemoveIPv6RouteFromSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip -6 route del {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    std::string interface_name = out_interface;
    if (interface_name.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route removal on Windows");
      return false;
    }
    const std::string command =
        fmt::format("netsh interface ipv6 delete route {}/{} \"{}\"", ip,
            prefix, interface_name);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv6 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error removing IPv6 route: {}", destination);
    return false;
  }
}

}  // namespace

using fptn::routing::RouteManager;

RouteManager::RouteManager(std::string out_interface_name,
    std::string tun_interface_name,
    fptn::common::network::IPv4Address vpn_server_ip,
    fptn::common::network::IPv4Address dns_server_ipv4,
    fptn::common::network::IPv6Address dns_server_ipv6,
    fptn::common::network::IPv4Address gateway_ipv4,
    fptn::common::network::IPv6Address gateway_ipv6,
    fptn::common::network::IPv4Address tun_interface_address_ipv4,
    fptn::common::network::IPv6Address tun_interface_address_ipv6
#if _WIN32
    ,
    bool enable_advanced_dns_management
#endif

    )
    : running_(false),
      out_interface_name_(std::move(out_interface_name)),
      tun_interface_name_(std::move(tun_interface_name)),
      vpn_server_ip_(std::move(vpn_server_ip)),
      dns_server_ipv4_(std::move(dns_server_ipv4)),
      dns_server_ipv6_(std::move(dns_server_ipv6)),
      gateway_ipv4_(std::move(gateway_ipv4)),
      gateway_ipv6_(std::move(gateway_ipv6)),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6))
#if _WIN32
      ,
      enable_advanced_dns_management_(enable_advanced_dns_management)
#endif
{
}

RouteManager::~RouteManager() {  // NOLINT(bugprone-exception-escape)
  if (running_) {
    Clean();
  }
}

bool RouteManager::Apply() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = true;
#if defined(__APPLE__) || defined(__linux__)
  detected_out_interface_name_ =
      (out_interface_name_.empty() ? GetDefaultNetworkInterfaceName()
                                   : out_interface_name_);
#endif
  detected_out_interface_name_ =
      (out_interface_name_.empty() ? GetDefaultNetworkInterfaceName()
                                   : out_interface_name_);
  detected_gateway_ipv4_ =
      gateway_ipv4_.IsEmpty() ? GetDefaultGatewayIPAddress() : gateway_ipv4_;

  SPDLOG_INFO("=== Setting up routing ===");
  SPDLOG_INFO("IPTABLES VPN SERVER IP:         {}", vpn_server_ip_.ToString());
  SPDLOG_INFO(
      "IPTABLES OUT NETWORK INTERFACE: {}", detected_out_interface_name_);
  SPDLOG_INFO(
      "IPTABLES GATEWAY IP:            {}", detected_gateway_ipv4_.ToString());
  SPDLOG_INFO(
      "IPTABLES DNS SERVER:            {}", dns_server_ipv4_.ToString());
#ifdef __linux__
  original_dns_servers_ = GetLinuxDnsServers(detected_out_interface_name_);
  for (const auto& dns : original_dns_servers_) {
    SPDLOG_INFO("Saved dns: {}", dns);
  }
  std::vector<std::string> commands = {fmt::format("systemctl start sysctl"),
      fmt::format("sysctl -w net.ipv4.ip_forward=1"),
      fmt::format("sysctl -w net.ipv6.conf.default.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.lo.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.forward=1"),
      fmt::format("sysctl -p"),
      // iptables
      fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      // IPv4 default & DNS route
      fmt::format("ip route add default dev {}", tun_interface_name_),
      fmt::format("ip route add {} dev {}", dns_server_ipv4_.ToString(),
          tun_interface_name_),  // via TUN
      // IPv6 default
      fmt::format("ip -6 route add default dev {}", tun_interface_name_),
      // exclude vpn server
      fmt::format("ip route add {} via {} dev {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString(), detected_out_interface_name_),
      // Allow DNS responses from TUN (sport 53, not dport 53)
      fmt::format("iptables -A OUTPUT -o {} -p udp --sport 53 -j ACCEPT",
          tun_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --sport 53 -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --sport 53 -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --sport 53 -j ACCEPT",
          tun_interface_name_),
      // Block DNS requests on physical interface
      fmt::format("iptables -A OUTPUT -o {} -p udp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --dport 53 -j DROP",
          detected_out_interface_name_),
      // Block DNS IPv6
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --dport 53 -j DROP",
          detected_out_interface_name_),
      // Block DoT IPv4
      fmt::format("iptables -A OUTPUT -o {} -p udp --dport 853 -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --dport 853 -j DROP",
          detected_out_interface_name_),
      // Block DoT IPv6
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --dport 853 -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --dport 853 -j DROP",
          detected_out_interface_name_),
      // Also allow DNS to specific DNS server IP
      fmt::format("iptables -A OUTPUT -d {} -p udp --dport 53 -j ACCEPT",
          dns_server_ipv4_.ToString()),
      fmt::format("iptables -A OUTPUT -d {} -p tcp --dport 53 -j ACCEPT",
          dns_server_ipv4_.ToString()),
      // DNS via resolvectl
      fmt::format("resolvectl dns {} {}", detected_out_interface_name_,
          dns_server_ipv4_.ToString()),
      fmt::format(
          "resolvectl default-route {} false", detected_out_interface_name_),
      fmt::format("resolvectl dns {} {}", tun_interface_name_,
          dns_server_ipv4_.ToString()),
      fmt::format("resolvectl default-route {} true", tun_interface_name_),
      fmt::format("resolvectl flush-caches")};

#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")",
          dns_server_ipv4_.ToString()),  // clean DNS
      fmt::format("sysctl -w net.inet.ip.forwarding=1"),
      fmt::format("sysctl -w net.inet6.ip6.forwarding=1"),
      fmt::format(
          R"(bash -c "printf 'nat on {findOutInterfaceName} from {tunInterfaceName}:network to any -> ({findOutInterfaceName})\npass out on {findOutInterfaceName} proto tcp from any to {vpnServerIP}\npass in on {findOutInterfaceName} proto tcp from {vpnServerIP} to any\npass in on {tunInterfaceName} proto tcp from any to any\npass out on {tunInterfaceName} proto tcp from any to any\npass in on {tunInterfaceName} proto udp from any to any\npass out on {tunInterfaceName} proto udp from any to any\n' > /tmp/pf.conf")",
          fmt::arg("findOutInterfaceName", detected_out_interface_name_),
          fmt::arg("tunInterfaceName", tun_interface_name_),
          fmt::arg("vpnServerIP", vpn_server_ip_.ToString())),
      fmt::format("pfctl -ef /tmp/pf.conf"),
      // IPv4 default & DNS route
      fmt::format(
          "route add -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route add -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("route add -host {} -interface {}",
          dns_server_ipv4_.ToString(), tun_interface_name_),  // via TUN
      // IPv6 routes
      fmt::format(
          "route add -inet6 -net ::0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route add -inet6 -net 8000::/1 -interface {}", tun_interface_name_),
      fmt::format("route add -inet6 default -interface {} 2>/dev/null || true",
          tun_interface_name_),
      // DNS IPv6 route
      fmt::format("route add -inet6 -host {} -interface {}",
          dns_server_ipv6_.ToString(), tun_interface_name_),
      // exclude vpn server & networks
      fmt::format("route add -host {} {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format("dscacheutil -flushcache"),
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")",
          dns_server_ipv4_.ToString())};

#elif _WIN32
  const std::string win_interface_number =
      GetWindowsInterfaceNumber(tun_interface_name_);
  const std::string interface_info =
      win_interface_number.empty() ? "" : " if " + win_interface_number;
  const std::string backup_dns_cmd = R"PSHELL(powershell -Command "
    if (-not (Test-Path \"$env:TEMP\\fptn_orig_dns.txt\")) {
      $interface = ')PSHELL" + detected_out_interface_name_ +
                                     R"PSHELL(';
      if (-not $interface) { $interface = ''; }
      if ($interface) {
        # IPv4
        $netshIPv4 = netsh interface ipv4 show dnsservers \"$interface\" 2>`$null;
        if ($netshIPv4 -match 'DHCP') {
          $output = @{IPv4='DHCP'};
        } else {
          $dns4 = Get-DnsClientServerAddress -InterfaceAlias $interface -AddressFamily IPv4 2>`$null | Select-Object -ExpandProperty ServerAddresses;
          if ($dns4) {
            $output = @{IPv4=($dns4 -join ',')};
          }
        }
        # IPv6
        $netshIPv6 = netsh interface ipv6 show dnsservers \"$interface\" 2>`$null;
        if ($netshIPv6 -match 'DHCP') {
          $output.IPv6 = 'DHCP';
        } else {
          $dns6 = Get-DnsClientServerAddress -InterfaceAlias $interface -AddressFamily IPv6 2>`$null | Select-Object -ExpandProperty ServerAddresses;
          if ($dns6) {
            $output.IPv6 = $dns6 -join ',';
          }
        }
        if ($output) {
          $output | ConvertTo-Json | Out-File \"$env:TEMP\\fptn_orig_dns.txt\" -Encoding UTF8;
        }
      }
    }")PSHELL";

  const std::string configure_dns_cmd = R"PSHELL(powershell -Command "
    $dns4 = ')PSHELL" + dns_server_ipv4_.ToString() +
                                        R"PSHELL(';
    $dns6 = ')PSHELL" + dns_server_ipv6_.ToString() +
                                        R"PSHELL(';
    $interface = ')PSHELL" + detected_out_interface_name_ +
                                        R"PSHELL(';
    if (-not $interface) { $interface = ''; }
    if ($interface) {
      # IPv4
      Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $dns4 -ErrorAction SilentlyContinue;
      netsh interface ipv4 set dnsservers name=\"$interface\" source=static address=$dns4 validate=no register=no 2>`$null;
      # IPv6
      Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $dns6 -ErrorAction SilentlyContinue;
      netsh interface ipv6 set dnsservers name=\"$interface\" source=static address=$dns6 validate=no register=no 2>`$null;
  }")PSHELL";

  const std::vector<std::string> commands = {
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2",
          vpn_server_ip_.ToString(), detected_gateway_ipv4_.ToString()),
      // Default gateway & dns
      fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}",
          tun_interface_address_ipv4_.ToString(), interface_info),
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}",
          dns_server_ipv4_.ToString(), tun_interface_address_ipv4_.ToString(),
          interface_info),  // via TUN
      // DNS
      enable_advanced_dns_management_ ? backup_dns_cmd
                                      : "echo \"No advanced DNS management\" ",
      enable_advanced_dns_management_ ? configure_dns_cmd
                                      : "echo \"No advanced DNS management\" ",
      fmt::format("netsh interface ip set dns name=\"{}\" static {}",
          tun_interface_name_, dns_server_ipv4_.ToString()),
      // IPv6
      fmt::format("netsh interface ipv6 add route ::/0 \"{}\" \"{}\" ",
          tun_interface_name_, tun_interface_address_ipv6_.ToString()),
      fmt::format("netsh interface ipv6 add dnsservers=\"{}\" \"{}\" index=1",
          tun_interface_name_, dns_server_ipv6_.ToString()),
      // Flush DNS cache
      "ipconfig /flushdns"};

#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  SPDLOG_INFO("=== Routing setup completed successfully ===");
  return true;
}

bool RouteManager::Clean() {  // NOLINT(bugprone-exception-escape)
  if (!running_) {
    SPDLOG_INFO("No need to clean rules!");
    return true;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = false;

  // clean dns ipv4
  for (const auto& ip : dns_routes_ipv4_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!out_interface_name_.empty()) {
        interface_name = out_interface_name_;
      } else {
        interface_name = GetDefaultNetworkInterfaceName();
      }
    } else {
      interface_name = tun_interface_name_;
    }
    RemoveIPv4RouteFromSystem(
        ip.destination, gateway_ipv4_.ToString(), interface_name);
  }
  dns_routes_ipv4_.clear();

  // clean dns ipv6
  for (const auto& ip : dns_routes_ipv6_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!out_interface_name_.empty()) {
        interface_name = out_interface_name_;
      } else {
        interface_name = GetDefaultNetworkInterfaceName();
      }
    } else {
      interface_name = tun_interface_name_;
    }
    RemoveIPv6RouteFromSystem(
        ip.destination, gateway_ipv6_.ToString(), interface_name);
  }
  dns_routes_ipv6_.clear();

  // clean route ipv4
  for (const auto& route : additional_routes_ipv4_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      RemoveIPv4RouteFromSystem(
          route.destination, gateway_ipv4_.ToString(), out_interface_name_);
    } else {
      // Include route - remove through VPN interface
      RemoveIPv4RouteFromSystem(route.destination,
          tun_interface_address_ipv4_.ToString(), tun_interface_name_);
    }
  }
  additional_routes_ipv4_.clear();

  // Remove additional IPv6 routes
  for (const auto& route : additional_routes_ipv6_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      RemoveIPv6RouteFromSystem(
          route.destination, gateway_ipv6_.ToString(), out_interface_name_);
    } else {
      // Include route - remove through VPN interface
      RemoveIPv6RouteFromSystem(route.destination,
          tun_interface_address_ipv6_.ToString(), tun_interface_name_);
    }
  }
  additional_routes_ipv6_.clear();

#ifdef __linux__
  std::vector<std::string> commands = {
      fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      // del routes
      fmt::format("ip route del default dev {}", tun_interface_name_),
      fmt::format("ip route del {} via {} dev {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString(), detected_out_interface_name_),
      // Delete DNS server route
      fmt::format("ip route del {} dev {}", dns_server_ipv4_.ToString(),
          tun_interface_name_),
      // Delete DNS to specific DNS server IP rules
      fmt::format("iptables -D OUTPUT -d {} -p udp --dport 53 -j ACCEPT",
          dns_server_ipv4_.ToString()),
      fmt::format("iptables -D OUTPUT -d {} -p tcp --dport 53 -j ACCEPT",
          dns_server_ipv4_.ToString()),
      // Delete DNS block rules IPv4
      fmt::format("iptables -D OUTPUT -o {} -p udp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p udp --dport 853 -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --dport 853 -j DROP",
          detected_out_interface_name_),
      // Delete DNS block rules IPv6
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --dport 53 -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --dport 853 -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --dport 853 -j DROP",
          detected_out_interface_name_),
      // Delete TUN allow rules IPv4
      fmt::format("iptables -D OUTPUT -o {} -p udp --sport 53 -j ACCEPT",
          tun_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --sport 53 -j ACCEPT",
          tun_interface_name_),
      // Delete TUN allow rules IPv6
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --sport 53 -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --sport 53 -j ACCEPT",
          tun_interface_name_)};

  // Restore DNS
  if (!original_dns_servers_.empty()) {
    std::string all_dns;
    for (const auto& dns : original_dns_servers_) {
      if (!all_dns.empty()) {
        all_dns += " ";
      }
      all_dns += dns;
    }
    commands.push_back(fmt::format(
        "resolvectl dns {} {}", detected_out_interface_name_, all_dns));
    commands.push_back(
        fmt::format("resolvectl domain {} .", detected_out_interface_name_));
    commands.push_back(fmt::format(
        "resolvectl default-route {} true", detected_out_interface_name_));
    SPDLOG_INFO("Restoring {} DNS servers for {}", original_dns_servers_.size(),
        detected_out_interface_name_);
  } else {
    commands.push_back(
        fmt::format("resolvectl revert {}", detected_out_interface_name_));
    SPDLOG_INFO("Reverting DNS to DHCP for {}", detected_out_interface_name_);
  }
  commands.emplace_back("resolvectl flush-caches");

#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")"),  // clean DNS
      fmt::format("pfctl -F all -f /etc/pf.conf"),
      // del routes
      fmt::format("route delete -host {} -interface {}",
          dns_server_ipv4_.ToString(),
          tun_interface_name_),  // via TUN
      fmt::format(
          "route delete -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route delete -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      // del IPv6 routes
      fmt::format(
          "route delete -inet6 -net ::0/1 -interface {}", tun_interface_name_),
      fmt::format("route delete -inet6 -net 8000::/1 -interface {}",
          tun_interface_name_),
      fmt::format("route delete -host {} {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")")  // clean DNS
  };
#elif _WIN32
  std::string current_interface_name = detected_out_interface_name_;
  if (current_interface_name.empty()) {
    current_interface_name = out_interface_name_;
  }
  if (current_interface_name.empty()) {
    current_interface_name = GetDefaultNetworkInterfaceName();
  }
  const std::string restore_dns_cmd = R"PSHELL(powershell -Command "
    $interface = ')PSHELL" + current_interface_name +
                                      R"PSHELL(';
    if ($interface) {
        if (Test-Path \"$env:TEMP\\fptn_orig_dns.txt\") {
            $config = Get-Content \"$env:TEMP\\fptn_orig_dns.txt\" -Raw | ConvertFrom-Json;
            # IPv4
            if ($config.IPv4 -eq 'DHCP') {
                netsh interface ip set dns \"$interface\" dhcp
            } elseif ($config.IPv4) {
                $dns4Servers = $config.IPv4 -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' };
                if ($dns4Servers.Count -gt 0) {
                    netsh interface ip set dns \"$interface\" static $($dns4Servers[0])
                    if ($dns4Servers.Count -gt 1) {
                        netsh interface ip add dns \"$interface\" $($dns4Servers[1]) index=2
                    }
                }
            }
            # IPv6
            if ($config.IPv6 -eq 'DHCP') {
                netsh interface ipv6 set dnsservers \"$interface\" dhcp
            } elseif ($config.IPv6) {
                $dns6Servers = $config.IPv6 -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' };
                if ($dns6Servers.Count -gt 0) {
                    netsh interface ipv6 set dnsservers \"$interface\" static $($dns6Servers[0]) primary
                    if ($dns6Servers.Count -gt 1) {
                        netsh interface ipv6 add dnsservers \"$interface\" $($dns6Servers[1]) index=2
                    }
                }
            }
            Remove-Item \"$env:TEMP\\fptn_orig_dns.txt\" -Force
        } else {
            netsh interface ip set dns \"$interface\" dhcp
            netsh interface ipv6 set dnsservers \"$interface\" dhcp
        }
    }")PSHELL";

  const std::vector<std::string> commands = {
      enable_advanced_dns_management_ ? restore_dns_cmd
                                      : "echo \"No advanced DNS management\" ",
      // Remove routes
      fmt::format(
          "route delete {} mask 255.255.255.255", vpn_server_ip_.ToString()),
      fmt::format("route delete 0.0.0.0 mask 0.0.0.0"),
      fmt::format(
          "route delete {} mask 255.255.255.255", dns_server_ipv4_.ToString()),
      fmt::format(
          "netsh interface ipv6 delete route ::/0 \"{}\"", tun_interface_name_),

      // Final cleanup
      "ipconfig /flushdns",

      // restore routing
      fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1",
          detected_gateway_ipv4_.ToString())};

#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  running_ = false;
  return true;
}

bool RouteManager::AddDnsRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;

  if (policy == RoutingPolicy::kExcludeFromVpn) {
    if (!detected_out_interface_name_.empty()) {
      interface_name = detected_out_interface_name_;
    } else if (!out_interface_name_.empty()) {
      interface_name = out_interface_name_;
    } else {
      interface_name = GetDefaultNetworkInterfaceName();
    }
    gateway_ip = gateway_ipv4_.ToString();
  } else {
    interface_name = tun_interface_name_;
    gateway_ip = tun_interface_address_ipv4_.ToString();
  }
  if (interface_name.empty()) {
    interface_name = fptn::routing::GetDefaultNetworkInterfaceName();
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv4 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv4_.contains(entry)) {
        dns_routes_ipv4_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv4RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO("DNS route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS route: {}", entry.destination);

        const std::unique_lock<std::mutex> lock(mutex_);
        dns_routes_ipv4_.erase(entry);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv4 route {}: {}", entry.destination,
          e.what());

      const std::unique_lock<std::mutex> lock(mutex_);
      dns_routes_ipv4_.erase(entry);
      status = false;
    }
  }

  return status;
}

bool RouteManager::AddDnsRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;

  if (policy == RoutingPolicy::kExcludeFromVpn) {
    if (!detected_out_interface_name_.empty()) {
      interface_name = detected_out_interface_name_;
    } else if (!out_interface_name_.empty()) {
      interface_name = out_interface_name_;
    } else {
      interface_name = GetDefaultNetworkInterfaceName();
    }
    gateway_ip = gateway_ipv6_.ToString();
  } else {
    interface_name = tun_interface_name_;
    gateway_ip = tun_interface_address_ipv6_.ToString();
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv6 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  if (gateway_ip.empty()) {
    SPDLOG_WARN("Cannot add DNS IPv6 routes: gateway IP is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv6_.contains(entry)) {
        dns_routes_ipv6_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv6RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO(
            "DNS IPv6 route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS IPv6 route: {}", entry.destination);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv6 route {}: {}", entry.destination,
          e.what());
      status = false;
    }
  }
  return status;
}

bool RouteManager::AddExcludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  const std::string interface_name = !detected_out_interface_name_.empty()
                                         ? detected_out_interface_name_
                                         : out_interface_name_;

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
        success = AddIPv6RouteToSystem(
            network, gateway_ipv6_.ToString(), interface_name);
      } else {
        success = AddIPv4RouteToSystem(
            network, gateway_ipv4_.ToString(), interface_name);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} exclude network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_WARN("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add exclude network '{}': {}", network, e.what());

      const std::unique_lock<std::mutex> lock(mutex_);
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};
      if (is_ipv6) {
        additional_routes_ipv6_.erase(entry);
      } else {
        additional_routes_ipv4_.erase(entry);
      }
      all_success = false;
    }
  }
  return all_success;
}

bool RouteManager::AddIncludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kIncludeInVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
        success = AddIPv6RouteToSystem(network,
            tun_interface_address_ipv6_.ToString(), tun_interface_name_);
      } else {
        success = AddIPv4RouteToSystem(network,
            tun_interface_address_ipv4_.ToString(), tun_interface_name_);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} include network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_ERROR("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add include network '{}': {}", network, e.what());
      all_success = false;
    }
  }

  return all_success;
}

// NOLINT(bugprone-exception-escape)
fptn::common::network::IPv4Address fptn::routing::ResolveDomain(
    const std::string& domain) {
  try {
    try {
      // error test
      boost::asio::ip::make_address(domain);
      return fptn::common::network::IPv4Address::Create(domain);
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
      // Not a valid IP address, proceed with domain name resolution
    }
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(domain, "");
    for (const auto& endpoint : endpoints) {
      return fptn::common::network::IPv4Address(
          endpoint.endpoint().address().to_string());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error resolving domain: {}", e.what());
  }
  return fptn::common::network::IPv4Address(domain);
}

fptn::common::network::IPv4Address fptn::routing::GetDefaultGatewayIPAddress() {
  try {
#ifdef __linux__
    const std::string command = "ip route get 8.8.8.8 | awk '{print $3; exit}'";
#elif __APPLE__
    const std::string command =
        "route get 8.8.8.8 | grep gateway | awk '{print $2}' ";
#elif _WIN32
    const std::string command =
        R"(cmd.exe /c FOR /f "tokens=3" %i in ('route print ^| find "0.0.0.0"') do @echo %i)";
#else
#error "Unsupported system!"
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    for (const auto& line : cmd_stdout) {
      std::string result = line;
      result.erase(
          // NOLINTNEXTLINE(modernize-use-ranges)
          std::remove_if(result.begin(), result.end(),
              [](char c) {
                /* Allow: a-z, A-Z, 0-9, dot, dash */
                return !std::isalnum(c) && c != '.' && c != '-' && c != '_';
              }),
          result.end());
      if (!result.empty()) {
        return ResolveDomain(result);
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return {};
}

fptn::common::network::IPv6Address
fptn::routing::GetDefaultGatewayIPv6Address() {
  try {
#ifdef __linux__
    const std::string command =
        "ip -6 route | grep default | head -1 | awk '{print $3}'";
#elif __APPLE__
    const std::string command =
        "route get -inet6 default | grep gateway | awk '{print $2}'";
#elif _WIN32
    const std::string command =
        R"(netsh interface ipv6 show routes | find "::/0" | head -1 | awk "{print $3}")";
#else
    return {};
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);

    for (const auto& line : cmd_stdout) {
      std::string result = line;
      std::erase_if(result, [](const char c) {
        return !std::isalnum(c) && c != ':' && c != '.' && c != '-';
      });
      if (!result.empty()) {
        return fptn::common::network::IPv6Address::Create(result);
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error getting IPv6 gateway: {}", ex.what());
  }
  return {};
}

std::string fptn::routing::GetDefaultNetworkInterfaceName() {
  std::string result;
  try {
#ifdef __linux__
    const std::string command =
        "ip route get 8.8.8.8 | awk '{print $5; exit}' ";
#elif __APPLE__
    const std::string command =
        "route get 8.8.8.8 | grep interface | awk '{print $2}' ";
#elif _WIN32
    const std::string command =
        R"(powershell -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Select-Object -First 1).InterfaceAlias")";
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    if (cmd_stdout.empty()) {
      SPDLOG_WARN("Warning: Default gateway IP address not found.");
      return {};
    }
    for (const auto& line : cmd_stdout) {
      result = line;
      result.erase(result.find_last_not_of(" \n\r\t") + 1);
      result.erase(0, result.find_first_not_of(" \n\r\t"));
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return result;
}
