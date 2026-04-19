/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>  // NOLINT(build/include_order)
#endif

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <argparse/argparse.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <fmt/ranges.h>  // NOLINT(build/include_order)

#include "common/logger/logger.h"
#include "common/network/ip_address.h"
#include "common/network/net_interface.h"

#include "config/config_file.h"
#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/time/time_provider.h"
#include "plugins/blacklist/domain_blacklist.h"
#include "routing/route_manager.h"
#include "utils/signal/main_loop.h"
#include "vpn/vpn_client.h"

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  try {
    const std::set<std::string> bypass_methods = {"obfuscation",
        /* chrome */
        "sni-reality-chrome147", "sni-reality-chrome146",
        "sni-reality-chrome145",
        /* Firefox */
        "sni-reality-firefox149",
        /* Yandex */
        "sni-reality-yandex26", "sni-reality-yandex25", "sni-reality-yandex24",
        /* Safari */
        "sni-reality-safari26"};
    const std::set<std::string> tunnel_modes = {"exclude", "include"};

    using fptn::protocol::https::obfuscator::GetObfuscatorByName;
    using fptn::protocol::https::obfuscator::GetObfuscatorNames;

    argparse::ArgumentParser args("fptn-client", FPTN_VERSION);
    // Required arguments
    args.add_argument("--access-token").required().help("Access token");
    // Optional arguments
    args.add_argument("--out-network-interface")
        .default_value("")
        .help("Network out interface");
    args.add_argument("--gateway-ip")
        .default_value("")
        .help("Your default gateway IPv4 address");
    args.add_argument("--gateway-ipv6")
        .default_value("")
        .help("Your default gateway IPv6 address");
    args.add_argument("--preferred-server")
        .default_value("")
        .help("Preferred server name (case-insensitive)");
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    args.add_argument("--tun-interface-ip")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP4)
        .help("Network interface IPv4 address");
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address");
    args.add_argument("--sni")
        .default_value(FPTN_DEFAULT_SNI)
        .help(
            "Domain name for SNI in TLS handshake (used to obfuscate VPN "
            "traffic)");
    args.add_argument("--blacklist-domains")
        .default_value(FPTN_CLIENT_DEFAULT_BLACKLIST_DOMAINS)
        .help(
            "Completely block access to the main domain AND all its "
            "subdomains\n"
            "Format: domain:example.com,domain:sub.site.org\n"
            "Example: domain:ria.ru blocks ria.ru and all *.ria.ru sites");
    // Method to bypass censorship
    args.add_argument("--bypass-method")
        .default_value("sni-reality-yandex25")
        .help(
            "Method to bypass censorship:\n"
            "  obfuscation            - TLS obfuscation\n"
            "  sni-reality-chrome147  - SNI reality with Chrome 146 handshake\n"
            "  sni-reality-chrome146  - SNI reality with Chrome 146 handshake\n"
            "  sni-reality-chrome145  - SNI reality with Chrome 145 handshake\n"
            "  sni-reality-firefox149 - SNI reality with Firefox 149 "
            "handshake\n"
            "  sni-reality-yandex26   - SNI reality with Yandex 26 handshake\n"
            "  sni-reality-yandex25   - SNI reality with Yandex 25 handshake\n"
            "  sni-reality-yandex24   - SNI reality with Yandex 24 handshake\n"
            "  sni-reality-safari26   - SNI reality with Safari 26 handshake\n")
        .action([&bypass_methods](const std::string& v) {
          if (!bypass_methods.contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid bypass method '{}'. Choose from: {}", v,
                    fmt::join(bypass_methods, ", ")));
          }
          return v;
        });
    // networks
    args.add_argument("--exclude-tunnel-networks")
        .default_value(FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS)
        .help(
            "Networks that always bypass VPN tunnel\n"
            "Traffic to these networks goes directly, never through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 10.0.0.0/8,192.168.0.0/16");
    args.add_argument("--include-tunnel-networks")
        .default_value("")
        .help(
            "Networks that always use VPN tunnel\n"
            "Traffic to these networks always goes through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 172.16.0.0/12,192.168.99.0/24");
    // Split-tunneling arguments
    args.add_argument("--enable-split-tunnel")
        .help(
            "Enable split tunneling - allows different traffic routing for "
            "different sites.\n"
            "When enabled, you can configure which sites use VPN and which go"
            "directly.\n"
            "Use with --split-tunnel-mode and --split-tunnel-domains for "
            "configuration.")
        .default_value(false)
        .nargs(1)
        .action([](const std::string& value) {
          if (value.empty()) {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "true") {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "false") {
            return false;
          }
          throw std::runtime_error("Value must be true/false");
        });
    args.add_argument("--split-tunnel-mode")
        .default_value("exclude")
        .help(
            "Defines traffic routing strategy for split tunneling.\n"
            "Modes:\n"
            "  exclude - Bypass VPN for specified domains, route all other "
            "traffic through VPN.\n"
            "  include - Route only specified domains through VPN, bypass VPN "
            "for all other traffic.\n")
        .action([&tunnel_modes](const std::string& v) {
          if (!tunnel_modes.contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid tunnel mode '{}'. Choose from: {}", v,
                    fmt::join(tunnel_modes, ", ")));
          }
          return v;
        });
    args.add_argument("--split-tunnel-domains")
        .default_value(FPTN_CLIENT_DEFAULT_SPLIT_TUNNEL_DOMAINS)
        .help(
            "List websites that should either use or bypass VPN\n"
            "\n"
            "How it works:\n"
            "  If --tunnel-mode=exclude: VPN skips these sites\n"
            "  If --tunnel-mode=include: VPN only for these sites\n"
            "Format: domain:com,domain:another.com,domain:sub.domainname.com");
    // parse cmd arguments
    try {
      args.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
      std::cerr << err.what() << std::endl;
      std::cerr << args;
      return EXIT_FAILURE;
    }

    if (fptn::logger::init("fptn-client-cli")) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    /* parse cmd args */
    const auto out_network_interface_name =
        args.get<std::string>("--out-network-interface");

    const auto param_gateway_ip = args.get<std::string>("--gateway-ip");
    const auto gateway_ip =
        fptn::common::network::IPv4Address::Create(param_gateway_ip);

    const auto param_gateway_ipv6 = args.get<std::string>("--gateway-ipv6");
    const auto gateway_ipv6 =
        fptn::common::network::IPv6Address::Create(param_gateway_ipv6);

    const auto preferred_server = args.get<std::string>("--preferred-server");

    const auto tun_interface_name =
        args.get<std::string>("--tun-interface-name");
    const auto tun_interface_address_ipv4 =
        fptn::common::network::IPv4Address::Create(
            args.get<std::string>("--tun-interface-ip"));
    const auto tun_interface_address_ipv6 =
        fptn::common::network::IPv6Address::Create(
            args.get<std::string>("--tun-interface-ipv6"));
    const auto sni = args.get<std::string>("--sni");

    /* check gateway address */
    const auto using_gateway_ip =
        gateway_ip.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPAddress()
            : fptn::common::network::IPv4Address::Create(gateway_ip);
    const auto using_gateway_ipv6 =
        gateway_ipv6.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPv6Address()
            : fptn::common::network::IPv6Address::Create(gateway_ipv6);
    if (using_gateway_ip.IsEmpty()) {
      SPDLOG_ERROR(
          "Unable to find the default gateway IP address. "
          "Please check your connection and make sure no other VPN is active. "
          "If the error persists, specify the gateway address in the FPTN "
          "settings using your router's IP "
          "address with the \"--gateway-ip\" option. If the issue "
          "remains unresolved, please contact the developer via Telegram "
          "@fptn_chat.");
      return EXIT_FAILURE;
    }

    const auto bypass_method = args.get<std::string>("--bypass-method");
    fptn::protocol::https::CensorshipStrategy censorship_strategy =
        fptn::protocol::https::CensorshipStrategy::kSniRealityModeYandex25;
    if (bypass_method == "obfuscation") {
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kTlsObfuscator;
    }
    /* Chrome */
    else if (bypass_method == "sni-reality-chrome147") {
      SPDLOG_INFO("Using Chrome 147 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeChrome147;
    } else if (bypass_method == "sni-reality-chrome146") {
      SPDLOG_INFO("Using Chrome 146 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeChrome146;
    } else if (bypass_method == "sni-reality-chrome145") {
      SPDLOG_INFO("Using Chrome 144 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeChrome145;
    }
    /* Firefox */
    else if (bypass_method == "sni-reality-firefox149") {
      SPDLOG_INFO("Using Firefox 149 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeFirefox149;
    }
    /* Yandex */
    else if (bypass_method == "sni-reality-yandex26") {
      SPDLOG_INFO("Using Yandex 26 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeYandex26;
    } else if (bypass_method == "sni-reality-yandex25") {
      SPDLOG_INFO("Using Yandex 25 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeYandex25;
    } else if (bypass_method == "sni-reality-yandex24") {
      SPDLOG_INFO("Using Yandex 25 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeYandex25;
    }
    /* Safari */
    else if (bypass_method == "sni-reality-safari26") {
      SPDLOG_INFO("Using Safari 26 handshake for censorship bypass");
      censorship_strategy =
          fptn::protocol::https::CensorshipStrategy::kSniRealityModeSafari26;
    }

    /* parse network lists */
    const auto exclude_networks_str =
        args.get<std::string>("--exclude-tunnel-networks");
    const auto include_networks_str =
        args.get<std::string>("--include-tunnel-networks");

    const std::vector<std::string> exclude_networks =
        fptn::common::utils::SplitCommaSeparated(exclude_networks_str);
    const std::vector<std::string> include_networks =
        fptn::common::utils::SplitCommaSeparated(include_networks_str);

    /* parse split-tunneling parameters */
    const bool enable_split_tunnel = args.get<bool>("--enable-split-tunnel");
    const auto tunnel_mode = args.get<std::string>("--split-tunnel-mode");
    const auto split_domains_str =
        args.get<std::string>("--split-tunnel-domains");
    const auto blacklist_domains_str =
        args.get<std::string>("--blacklist-domains");

    const std::vector<std::string> split_domains =
        fptn::common::utils::SplitCommaSeparated(split_domains_str);
    const std::vector<std::string> blacklist_domains =
        fptn::common::utils::SplitCommaSeparated(blacklist_domains_str);

    /* check config */
    const auto access_token = args.get<std::string>("--access-token");
    fptn::config::ConfigFile config(access_token, sni, censorship_strategy);
    fptn::utils::speed_estimator::ServerInfo selected_server;
    try {
      config.Parse();
      if (!preferred_server.empty()) {
        auto server_opt = config.GetServer(preferred_server);
        if (server_opt.has_value()) {
          selected_server = std::move(*server_opt);
        } else {
          SPDLOG_WARN("Server '{}' does not exist! Check your token!",
              preferred_server);
          selected_server = config.FindFastestServer(15);
        }
      } else {
        selected_server = config.FindFastestServer(15);
      }
    } catch (const std::runtime_error& err) {
      SPDLOG_ERROR("Config error: {}", err.what());
      return EXIT_FAILURE;
    }
    const auto server_ip = fptn::routing::ResolveDomain(selected_server.host);
    if (server_ip.IsEmpty()) {
      SPDLOG_ERROR("DNS resolve error: {}", selected_server.host);
      return EXIT_FAILURE;
    }

    SPDLOG_INFO(
        "\n--- Starting client ---\n"
        "VERSION:            {}\n"
        "SELECTED SERVER:    {}\n"
        "SNI:                {}\n"
        "GATEWAY IP:         {}\n"
        "NETWORK INTERFACE:  {}\n"
        "VPN SERVER NAME:    {}\n"
        "VPN SERVER IP:      {}\n"
        "VPN SERVER PORT:    {}\n"
        "TUN INTERFACE IPv4: {}\n"
        "TUN INTERFACE IPv6: {}\n"
        "BYPASS-METHOD:      {}\n"
        "EXCLUDE NETWORKS:   {}\n"
        "INCLUDE NETWORKS:   {}\n"
        "SPLIT TUNNEL:       {}\n"
        "TUNNEL MODE:        {}\n"
        "TUNNEL DOMAINS:     {}\n"
        "BLACKLIST DOMAINS:  {}\n",
        FPTN_VERSION, selected_server.name, sni, using_gateway_ip.ToString(),
        out_network_interface_name, selected_server.name, selected_server.host,
        selected_server.port, tun_interface_address_ipv4.ToString(),
        tun_interface_address_ipv6.ToString(), bypass_method,
        exclude_networks_str, include_networks_str,
        enable_split_tunnel ? "enabled" : "disabled", tunnel_mode,
        split_domains_str, blacklist_domains_str);

    /* auth & dns */
    auto http_client = std::make_unique<fptn::vpn::http::Client>(server_ip,
        selected_server.port, tun_interface_address_ipv4,
        tun_interface_address_ipv6, sni, selected_server.md5_fingerprint,
        censorship_strategy);
    const bool status =
        http_client->Login(config.GetUsername(), config.GetPassword());
    if (!status) {
      SPDLOG_ERROR("The username or password you entered is incorrect");
      return EXIT_FAILURE;
    }
    const auto [dnsServerIPv4, dnsServerIPv6] = http_client->GetDns();
    if (dnsServerIPv4.IsEmpty() || dnsServerIPv6.IsEmpty()) {
      SPDLOG_ERROR("DNS server error! Check your connection!");
      return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtual_network_interface =
        std::make_unique<fptn::common::network::TunInterface>(
            fptn::common::network::TunInterface::Config{
                .name = tun_interface_name,
                .ipv4_addr = tun_interface_address_ipv4,
                .ipv4_netmask = 30,  // IPv4 netmask
                .ipv6_addr = tun_interface_address_ipv6,
                .ipv6_netmask = 126  // IPv6 netmask
            });

    /* route manager */
    auto route_manager = std::make_shared<fptn::routing::RouteManager>(
        out_network_interface_name, tun_interface_name, server_ip,
        dnsServerIPv4, dnsServerIPv6, using_gateway_ip, using_gateway_ipv6,
        tun_interface_address_ipv4, tun_interface_address_ipv6
#if _WIN32
        ,
        false
#endif
    );  // NOLINT

    /* plugins */
    std::vector<fptn::plugin::BasePluginPtr> client_plugins;
    if (!blacklist_domains.empty()) {
      auto blacklist_plugin = std::make_unique<fptn::plugin::DomainBlacklist>(
          blacklist_domains, route_manager);
      client_plugins.push_back(std::move(blacklist_plugin));
    }

    if (enable_split_tunnel) {
      const auto policy = tunnel_mode == "exclude"
                              ? fptn::routing::RoutingPolicy::kExcludeFromVpn
                              : fptn::routing::RoutingPolicy::kIncludeInVpn;
      auto split_tunnel_plugin = std::make_unique<fptn::plugin::Tunneling>(
          split_domains, route_manager, policy);
      client_plugins.push_back(std::move(split_tunnel_plugin));
    }

    /* vpn client */
    fptn::vpn::VpnClient vpn_client(std::move(http_client),
        std::move(virtual_network_interface), dnsServerIPv4, dnsServerIPv6,
        std::move(client_plugins));
    vpn_client.Start();

    // Update tun name to actual device name (may differ on macOS)
    route_manager->UpdateTunInterfaceName(vpn_client.GetInterfaceName());

    // Wait for the WebSocket tunnel to establish
    constexpr std::chrono::seconds kTimeout(10);
    const auto start = std::chrono::steady_clock::now();
    while (!vpn_client.IsStarted()) {
      if (std::chrono::steady_clock::now() - start > kTimeout) {
        SPDLOG_ERROR("Couldn't open websocket tunnel!");
        return EXIT_FAILURE;
      }
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    /* apply mandatory network routes */
    route_manager->Apply();
    if (!exclude_networks.empty()) {
      route_manager->AddExcludeNetworks(exclude_networks);
    }
    if (!include_networks.empty()) {
      route_manager->AddIncludeNetworks(include_networks);
    }

    /* start event loop */
    fptn::utils::WaitForSignal(vpn_client);

    /* clean */
    route_manager->Clean();
    vpn_client.Stop();
    spdlog::shutdown();
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
