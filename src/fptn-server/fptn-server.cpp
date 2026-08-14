/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <filesystem>
#include <iostream>
#include <memory>
#include <utility>

#include <boost/asio.hpp>
#include <fmt/ranges.h>  // NOLINT(build/include_order)

#include "common/jwt_token/token_manager.h"
#include "common/logger/logger.h"
#include "common/network/ip_address.h"

#include "fptn-protocol-lib/time/time_provider.h"

#include "config/server_config.h"
#include "filter/filters/antiscan/antiscan.h"
#include "filter/filters/bittorrent/bittorrent.h"
#include "filter/manager.h"
#include "nat/table.h"
#include "network/virtual_interface.h"
#include "routing/route_manager.h"
#include "statistic/metrics.h"
#include "user/user_manager.h"
#include "vpn/manager.h"
#include "web/server.h"

namespace {

void WaitForSignal() {
  boost::asio::io_context io_context;
  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM /*,SIGQUIT*/);
  signals.async_wait([&](auto, auto) { io_context.stop(); });
  io_context.run();
}
}  // namespace

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  try {
    /* Init config */
    auto config = std::make_shared<fptn::config::ServerConfig>(argc, argv);
    if (!config->Parse()) {
      return EXIT_FAILURE;
    }
    if (!std::filesystem::exists(config->ServerCrt()) ||
        !std::filesystem::exists(config->ServerKey())) {
      SPDLOG_ERROR("SSL certificate or key file does not exist!");
      return EXIT_FAILURE;
    }

    /* Init logger */
    if (fptn::logger::init("fptn-server")) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    fptn::time::TimeProvider::Instance();

    /* Init route manager */
    auto route_manager = std::make_unique<fptn::routing::RouteManager>(
        config->OutNetworkInterface(), config->TunInterfaceName());
    /* Init virtual network interface */

    auto virtual_network_interface =
        std::make_unique<fptn::network::VirtualInterface>(
            config->TunInterfaceName(), config->MtuSize(),
            std::move(route_manager),
            fptn::common::network::TunInterface::Config{
                .ipv4_addr = config->TunInterfaceIPv4(),
                .ipv4_netmask = config->TunInterfaceNetworkIPv4Mask(),
                .ipv6_addr = config->TunInterfaceIPv6(),
                .ipv6_netmask = config->TunInterfaceNetworkIPv6Mask()});

    /* Init web server */
    auto token_manager =
        std::make_shared<fptn::common::jwt_token::TokenManager>(
            config->ServerCrt(), config->ServerKey());
    /* Init user manager */
    auto user_manager = std::make_shared<fptn::user::UserManager>(
        config->UserFile(), config->UseRemoteServerAuth(),
        config->RemoteServerAuthHost(), config->RemoteServerAuthPort());
    /* Init NAT */
    auto nat_table = std::make_shared<fptn::nat::Table>(
        fptn::nat::Table::Config{.tun_ipv4 = config->TunInterfaceIPv4(),
            .tun_ipv4_network = config->TunInterfaceNetworkIPv4Address(),
            .tun_network_ipv4_mask = config->TunInterfaceNetworkIPv4Mask(),
            .tun_ipv6 = config->TunInterfaceIPv6(),
            .tun_ipv6_network = config->TunInterfaceNetworkIPv6Address(),
            .tun_network_ipv6_mask = config->TunInterfaceNetworkIPv6Mask()});
    /* Init prometheus */
    auto prometheus = std::make_shared<fptn::statistic::Metrics>();
    /* Init webserver */
    auto web_server = std::make_unique<fptn::web::Server>(config->ServerPort(),
        nat_table, user_manager, token_manager, prometheus,
        config->PrometheusAccessKey(), config->TunInterfaceIPv4(),
        config->TunInterfaceIPv6(),
        /* probing */
        config->EnableDetectProbing(), config->DefaultProxyDomain(),
        config->AllowedSniList(),
        /* sessions */
        config->MaxActiveSessionsPerUser(),
        /* External IPs */
        config->ServerExternalIPs());

    /* init packet filter */
    auto filter_manager = std::make_shared<fptn::filter::Manager>();
    if (config->DisableBittorrent()) {  // block bittorrent traffic
      filter_manager->Add(std::make_shared<fptn::filter::BitTorrent>());
    }
    // Prevent sending requests to the VPN virtual network from the client
    filter_manager->Add(std::make_shared<fptn::filter::AntiScan>(
        /* IPv4 */
        config->TunInterfaceIPv4(), config->TunInterfaceNetworkIPv4Address(),
        config->TunInterfaceNetworkIPv4Mask(),
        /* IPv6 */
        config->TunInterfaceIPv6(), config->TunInterfaceNetworkIPv6Address(),
        config->TunInterfaceNetworkIPv6Mask()));

    SPDLOG_INFO(
        "\n--- Starting server---\n"
        "VERSION:           {}\n"
        "NETWORK INTERFACE: {}\n"
        "VPN NETWORK IPv4:  {}\n"
        "VPN NETWORK IPv6:  {}\n"
        "VPN SERVER PORT:   {}\n"
        "DETECT_PROBING:    {}\n"
        "DEFAULT_PROXY_DOMAIN: {}\n"
        "ALLOWED_SNI_LIST:     {}\n"
        "MAX_ACTIVE_SESSIONS_PER_USER: {}\n",
        FPTN_VERSION,
        // Network settings
        config->OutNetworkInterface(),
        config->TunInterfaceNetworkIPv4Address().ToString(),
        config->TunInterfaceNetworkIPv6Address().ToString(),
        config->ServerPort(),
        // Probing settings
        config->EnableDetectProbing() ? "YES" : "NO",
        config->DefaultProxyDomain(),
        fmt::format("[{}]", fmt::join(config->AllowedSniList(), ", ")),
        // max session
        config->MaxActiveSessionsPerUser());

    // Init vpn manager
    fptn::vpn::Manager manager(std::move(web_server),
        std::move(virtual_network_interface), nat_table, filter_manager,
        prometheus);

    /* start/wait/stop */
    manager.Start();
    WaitForSignal();
    manager.Stop();

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
