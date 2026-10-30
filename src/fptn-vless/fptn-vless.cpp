/*
 * fptn-vless: connect to an FPTN server with an access token and expose the
 * tunnel to the LAN as a plain VLESS inbound.
 *
 * Unlike fptn-client-cli this program never creates a network adapter and
 * never touches routes or DNS: the tunnel terminates in a userspace TCP/IP
 * stack (lwIP). Closing it - cleanly or not - leaves Windows exactly as it was.
 *
 * Everything is controlled from a local web page (see dashboard.h, app.h).
 * On Windows the program lives in the tray and puts a shortcut on the desktop.
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <argparse/argparse.hpp>
#include <boost/asio.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)

#include "common/logger/logger.h"

#include "config/config_file.h"
#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/time/time_provider.h"

#include "fptn-vless/app.h"
#include "fptn-vless/dashboard.h"
#include "fptn-vless/events.h"
#include "fptn-vless/platform.h"
#include "fptn-vless/tunnel_check.h"
#include "fptn-vless/tunnel_manager.h"
#include "fptn-vless/userspace_stack.h"

namespace {

using fptn::protocol::https::CensorshipStrategy;
using fptn::protocol::connection::strategies::ConnectionStrategy;

const std::map<std::string, CensorshipStrategy>& BypassMethods() {
  static const std::map<std::string, CensorshipStrategy> kMethods = {
      {"obfuscation", CensorshipStrategy::kTlsObfuscator},
      {"sni-spoofing-chrome-149", CensorshipStrategy::kSniRealityModeChrome149},
      {"sni-spoofing-chrome-148", CensorshipStrategy::kSniRealityModeChrome148},
      {"sni-spoofing-chrome-147", CensorshipStrategy::kSniRealityModeChrome147},
      {"sni-spoofing-chrome-146", CensorshipStrategy::kSniRealityModeChrome146},
      {"sni-spoofing-chrome-145", CensorshipStrategy::kSniRealityModeChrome145},
      {"sni-spoofing-firefox-151",
          CensorshipStrategy::kSniRealityModeFirefox151},
      {"sni-spoofing-firefox-150",
          CensorshipStrategy::kSniRealityModeFirefox150},
      {"sni-spoofing-firefox-149",
          CensorshipStrategy::kSniRealityModeFirefox149},
      {"sni-spoofing-yandex-26-4", CensorshipStrategy::kSniRealityModeYandex26_4},
      {"sni-spoofing-yandex-26-3", CensorshipStrategy::kSniRealityModeYandex26_3},
      {"sni-spoofing-yandex-25", CensorshipStrategy::kSniRealityModeYandex25},
      {"sni-spoofing-yandex-24", CensorshipStrategy::kSniRealityModeYandex24},
      {"sni-spoofing-safari-26-5", CensorshipStrategy::kSniRealityModeSafari26_5},
      {"sni-spoofing-safari-26-4", CensorshipStrategy::kSniRealityModeSafari26_4},
  };
  return kMethods;
}

const std::map<std::string, ConnectionStrategy>& ConnectionStrategies() {
  static const std::map<std::string, ConnectionStrategy> kStrategies = {
      {"rolling-tunnel", ConnectionStrategy::kSingleRollingTunnel},
      {"dual-rolling-tunnel", ConnectionStrategy::kDualRollingTunnel},
      {"triple-rolling-tunnel", ConnectionStrategy::kTripleRollingTunnel},
  };
  return kStrategies;
}

// IPv4 addresses of this PC. The first one is the address the OS would use to
// reach the internet (normally the LAN address), the rest are other adapters.
std::vector<std::string> LanAddresses() {
  std::vector<std::string> result;
  const auto add = [&result](const boost::asio::ip::address& address) {
    if (!address.is_v4() || address.is_loopback() || address.is_unspecified()) {
      return;
    }
    const std::string text = address.to_string();
    if (text.rfind("169.254.", 0) == 0) {  // link-local, not a real address
      return;
    }
    if (std::find(result.begin(), result.end(), text) == result.end()) {
      result.push_back(text);
    }
  };
  boost::asio::io_context io;
  boost::system::error_code ec;
  {
    // A UDP "connect" sends nothing: it only asks the OS which local address
    // it would use for that destination.
    boost::asio::ip::udp::socket probe(io);
    probe.open(boost::asio::ip::udp::v4(), ec);
    if (!ec) {
      probe.connect({boost::asio::ip::make_address("8.8.8.8"), 53}, ec);
    }
    if (!ec) {
      const auto endpoint = probe.local_endpoint(ec);
      if (!ec) {
        add(endpoint.address());
      }
    }
  }
  const std::string host = boost::asio::ip::host_name(ec);
  if (!ec) {
    boost::asio::ip::tcp::resolver resolver(io);
    const auto found = resolver.resolve(host, "", ec);
    if (!ec) {
      for (const auto& entry : found) {
        add(entry.endpoint().address());
      }
    }
  }
  return result;
}


template <typename... Args>
void ConsoleError(fmt::format_string<Args...> format, Args&&... args) {
  const std::string text = fmt::format(format, std::forward<Args>(args)...);
  SPDLOG_ERROR("{}", text);
  std::cerr << "\nERROR: " << text << std::endl;
}

}  // namespace

int main(int argc, char* argv[]) {
  argparse::ArgumentParser args("fptn-vless", FPTN_VERSION);
  args.add_argument("--access-token")
      .default_value("")
      .help("FPTN access token (optional: it can be entered on the control "
            "page, where it is also remembered)");
  args.add_argument("--token-file")
      .default_value("")
      .help("Text file with the access token");
  args.add_argument("--server")
      .default_value("")
      .help("Server name to connect to and stay on (default: the fastest)");
  args.add_argument("--no-failover")
      .default_value(false)
      .implicit_value(true)
      .help("Stay on the chosen server, never switch to another one");
  args.add_argument("--scan-interval")
      .default_value(300)
      .scan<'i', int>()
      .help("Seconds between response-time checks of all servers (0 = never)");
  args.add_argument("--dashboard-port")
      .default_value(10801)
      .scan<'i', int>()
      .help("Port of the local control page http://127.0.0.1:PORT");
  args.add_argument("--no-browser")
      .default_value(false)
      .implicit_value(true)
      .help("Do not open the control page in the browser automatically");
  args.add_argument("--no-tray")
      .default_value(false)
      .implicit_value(true)
      .help("No tray icon, keep the console window");
  args.add_argument("--no-shortcut")
      .default_value(false)
      .implicit_value(true)
      .help("Do not create a desktop shortcut");
  args.add_argument("--verbose")
      .default_value(false)
      .implicit_value(true)
      .help("Show the detailed library log in the console (it is always "
            "written to logs/fptn-vless.log)");
  args.add_argument("--link-host")
      .default_value("")
      .help("Address to put into the vless:// link (default: detected)");
  args.add_argument("--listen")
      .default_value("0.0.0.0")
      .help("Address of the VLESS inbound (0.0.0.0 = whole LAN)");
  args.add_argument("--port").default_value(10800).scan<'i', int>().help(
      "Port of the VLESS inbound");
  args.add_argument("--uuid")
      .default_value("")
      .help("VLESS user id. Empty: derived from the access token");
  args.add_argument("--sni").default_value(FPTN_DEFAULT_SNI).help("TLS SNI");
  args.add_argument("--bypass-method")
      .default_value("sni-spoofing-yandex-26-4")
      .help("Same values as fptn-client-cli --bypass-method");
  args.add_argument("--connection-strategy")
      .default_value("rolling-tunnel")
      .help("rolling-tunnel | dual-rolling-tunnel | triple-rolling-tunnel");
  args.add_argument("--mtu-size").default_value(FPTN_DEFAULT_MTU_SIZE)
      .scan<'i', int>().help("MTU of the userspace stack");

  try {
    args.parse_args(argc, argv);
  } catch (const std::exception& err) {
    std::cerr << err.what() << std::endl << args;
    return EXIT_FAILURE;
  }

  const int dashboard_port = args.get<int>("--dashboard-port");
  if (dashboard_port < 1 || dashboard_port > 65535) {
    std::cerr << "--dashboard-port is out of range\n";
    return EXIT_FAILURE;
  }
  const std::string panel_url = fmt::format("http://127.0.0.1:{}/", dashboard_port);

  // Started a second time (e.g. from the desktop shortcut while the program
  // sits in the tray): just show the control page of the running copy.
  if (!fptn::vless::platform::AcquireSingleInstance()) {
    fptn::vless::platform::OpenUrl(panel_url);
    std::cout << "fptn-vless is already running. Control page: " << panel_url
              << std::endl;
    return EXIT_SUCCESS;
  }

  if (!fptn::logger::init("fptn-vless")) {
    std::cerr << "File logging unavailable, logging to console only\n";
  }
  if (!args.get<bool>("--verbose")) {
    // The console shows only what matters; everything stays in the log file.
    spdlog::default_logger()->flush();
    const auto& sinks = spdlog::default_logger()->sinks();
    if (!sinks.empty()) {
      sinks.front()->set_level(spdlog::level::off);
    }
  }
  fptn::vless::SetEventSink([](const std::string& line) {
    static std::mutex console_mu;
    const std::lock_guard<std::mutex> lock(console_mu);
    std::cout << line << std::endl;
  });
  SPDLOG_INFO("fptn-vless {} started", FPTN_VERSION);
  fptn::time::TimeProvider::Instance();

  try {
    /* ---- options ---- */
    const auto sni = args.get<std::string>("--sni");
    const auto bypass_name = args.get<std::string>("--bypass-method");
    const auto strategy_name = args.get<std::string>("--connection-strategy");
    const auto bypass_it = BypassMethods().find(bypass_name);
    const auto strategy_it = ConnectionStrategies().find(strategy_name);
    if (bypass_it == BypassMethods().end()) {
      ConsoleError("Unknown --bypass-method '{}'", bypass_name);
      return EXIT_FAILURE;
    }
    if (strategy_it == ConnectionStrategies().end()) {
      ConsoleError("Unknown --connection-strategy '{}'", strategy_name);
      return EXIT_FAILURE;
    }
    const int mtu_size = args.get<int>("--mtu-size");
    const int port = args.get<int>("--port");
    const int scan_interval = args.get<int>("--scan-interval");
    if (port < 1 || port > 65535 || mtu_size < 576 || mtu_size > 65535 ||
        scan_interval < 0) {
      ConsoleError("--port, --mtu-size or --scan-interval is out of range");
      return EXIT_FAILURE;
    }
    if (const auto text = args.get<std::string>("--uuid"); !text.empty()) {
      fptn::vless::Uuid probe;
      if (!fptn::vless::ParseUuid(text, probe)) {
        ConsoleError("--uuid is not a valid UUID");
        return EXIT_FAILURE;
      }
    }

    /* ---- optional token from the command line ---- */
    std::optional<std::string> cli_token;
    if (const auto text = args.get<std::string>("--access-token"); !text.empty()) {
      cli_token = text;
    } else if (const auto path = args.get<std::string>("--token-file");
               !path.empty()) {
      std::ifstream file(path, std::ios::binary);
      if (!file) {
        ConsoleError("Cannot open --token-file '{}'", path);
        return EXIT_FAILURE;
      }
      cli_token = std::string(std::istreambuf_iterator<char>(file),
          std::istreambuf_iterator<char>());
    }

    /* ---- userspace stack instead of an OS adapter ---- */
    auto& stack = fptn::vless::UserspaceStack::Instance();
    fptn::vless::UserspaceStack::Config stack_config;
    stack_config.ipv4 = FPTN_CLIENT_DEFAULT_ADDRESS_IP4;
    stack_config.mtu = mtu_size;  // DNS is set when a tunnel comes up
    if (!stack.Start(stack_config)) {
      ConsoleError("Cannot start the userspace network stack");
      return EXIT_FAILURE;
    }

    /* ---- the application ---- */
    fptn::vless::TunnelManager::Options tunnel_options;
    tunnel_options.sni = sni;
    tunnel_options.censorship_strategy = bypass_it->second;
    tunnel_options.connection_strategy = strategy_it->second;
    tunnel_options.mtu_size = mtu_size;

    fptn::vless::AppOptions app_options;
    app_options.failover.failover = !args.get<bool>("--no-failover");
    app_options.failover.scan_interval = std::chrono::seconds(scan_interval);
    app_options.listen = args.get<std::string>("--listen");
    app_options.port = port;
    app_options.uuid_override = args.get<std::string>("--uuid");
    app_options.link_host = args.get<std::string>("--link-host");
    app_options.preferred_server = args.get<std::string>("--server");
    app_options.reserved_port = dashboard_port;

    fptn::vless::AppDeps deps;
    deps.make_tunnels = [&](const std::string& token)
        -> std::unique_ptr<fptn::vless::ITunnels> {
      fptn::config::ConfigFile config(token, sni, bypass_it->second);
      config.Parse();
      return std::make_unique<fptn::vless::TunnelManager>(config, tunnel_options);
    };
    deps.lan_hosts = []() { return LanAddresses(); };
    deps.firewall_status = [](int port) {
      using fptn::vless::FirewallStatus;
      using fptn::vless::platform::FirewallState;
      switch (fptn::vless::platform::FirewallRuleState(port)) {
        case FirewallState::kOpen: return FirewallStatus::kOpen;
        case FirewallState::kClosed: return FirewallStatus::kClosed;
        case FirewallState::kUnknown: return FirewallStatus::kUnknown;
        default: return FirewallStatus::kUnsupported;
      }
    };
    deps.firewall_add = [](int port) {
      return fptn::vless::platform::AddFirewallRule(port);
    };
    deps.carries_traffic = [&stack]() {
      return fptn::vless::TunnelCarriesTraffic(stack);
    };
    deps.full_check = [&stack]() {
      return fptn::vless::CheckTunnel(stack).Summary();
    };

    boost::asio::io_context ioc;
    auto work_guard = boost::asio::make_work_guard(ioc);
    fptn::vless::SettingsStore store(fptn::vless::SettingsStore::DefaultDirectory());
    fptn::vless::App app(ioc, stack, store, app_options, deps);

    fptn::vless::DashboardApi api;
    api.state_json = [&app]() { return app.StateJson(); };
    api.post = [&app](const std::string& action, const std::string& query,
                   const std::string& body) {
      return app.HandlePost(action, query, body);
    };
    fptn::vless::Dashboard dashboard(
        ioc, static_cast<std::uint16_t>(dashboard_port), api);
    if (!dashboard.Start()) {
      ConsoleError("Port {} for the control page is busy. Use "
                   "--dashboard-port <other>.", dashboard_port);
      stack.Stop();
      return EXIT_FAILURE;
    }

    /* ---- desktop integration (Windows) ---- */
    if (!args.get<bool>("--no-shortcut") &&
        fptn::vless::platform::EnsureDesktopShortcut()) {
      fptn::vless::Notify("Ярлык fptn-vless создан на рабочем столе");
    }
    std::unique_ptr<fptn::vless::platform::Tray> tray;
    if (!args.get<bool>("--no-tray")) {
      fptn::vless::platform::Tray::Callbacks callbacks;
      callbacks.on_open = [panel_url]() {
        fptn::vless::platform::OpenUrl(panel_url);
      };
      callbacks.on_exit = [&ioc]() { ioc.stop(); };
      tray = std::make_unique<fptn::vless::platform::Tray>(
          std::move(callbacks), "fptn-vless");
      if (tray->Start()) {
        if (fptn::vless::platform::OwnsConsole()) {
          fptn::vless::platform::HideConsole();  // started by a shortcut
          tray->Balloon("fptn-vless",
              "Работает в трее. Двойной щелчок по значку открывает панель.");
        }
      } else {
        tray.reset();
      }
    }

    std::cout << "fptn-vless " << FPTN_VERSION << "\nControl page: " << panel_url
              << "\nCtrl+C (or Exit in the tray menu) to stop.\n" << std::endl;
    app.Start(cli_token);
    if (!args.get<bool>("--no-browser")) {
      fptn::vless::platform::OpenUrl(panel_url);
    }

    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) { ioc.stop(); });
    ioc.run();

    /* ---- shutdown: nothing to roll back on the OS ---- */
    tray.reset();
    dashboard.Stop();
    app.Shutdown();
    stack.Stop();
    spdlog::shutdown();
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    ConsoleError("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    ConsoleError("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
