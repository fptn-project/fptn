#pragma once

/*
 * The application behind the control page. It owns the whole life cycle:
 *
 *   no_token -> (token) -> scanning -> ready -> connecting -> connected
 *                              ^          ^                      |
 *                              |          +------ disconnect ----+
 *                              +-- forget token / new token -----+
 *
 * Everything the page can do is an action that runs on one worker thread
 * (one at a time, `busy` says which); the page polls StateJson().
 * FPTN itself is reached only through ITunnels, so this class is tested with a
 * fake set of servers.
 */

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include "fptn-vless/failover.h"
#include "fptn-vless/settings_store.h"
#include "fptn-vless/tunnels.h"
#include "fptn-vless/userspace_stack.h"
#include "fptn-vless/vless_server.h"

namespace fptn::vless {

// Helpers (also used by tests).
std::string CleanToken(const std::string& raw);  // drops spaces/newlines/quotes
Uuid DeriveUuid(const std::string& token);       // same token -> same UUID
std::string MakeLink(const Uuid& uuid, const std::string& host, int port);

enum class FirewallStatus { kUnsupported, kUnknown, kOpen, kClosed };

struct AppOptions {
  FailoverController::Options failover;  // failover/scan_interval/timings
  std::string listen = "0.0.0.0";
  int port = 10800;
  std::string uuid_override;   // empty: derived from the token
  std::string link_host;       // empty: detected
  std::string preferred_server;  // --server: connect to it (and keep it)
  int reserved_port = 0;         // the control page's port: not allowed for VLESS
};

struct AppDeps {
  // Parses the token and prepares the servers. Throws with a readable message.
  std::function<std::unique_ptr<ITunnels>(const std::string& token)>
      make_tunnels;
  std::function<std::vector<std::string>()> lan_hosts;
  // Quick yes/no: does the live tunnel carry traffic? (optional)
  std::function<bool()> carries_traffic;
  // Full check, returns a one-line summary. (optional)
  std::function<std::string()> full_check;
  // Windows firewall (optional; without them the page hides that block).
  std::function<FirewallStatus(int port)> firewall_status;
  // Adds the allow rule (UAC prompt). Empty string = ok, else the reason.
  std::function<std::string(int port)> firewall_add;
};

class App {
 public:
  App(boost::asio::io_context& ioc,
      UserspaceStack& stack,
      SettingsStore& store,
      AppOptions options,
      AppDeps deps);
  ~App();
  App(const App&) = delete;
  App& operator=(const App&) = delete;

  // `cli_token` (from --access-token/--token-file) wins over the saved one.
  // With a token, the program connects by itself.
  void Start(const std::optional<std::string>& cli_token);

  // Actions of the page. All return at once; false = busy or not possible now.
  bool SubmitToken(const std::string& token, bool remember);
  bool Connect(std::optional<std::size_t> index);  // nullopt = fastest
  bool Disconnect();
  bool Rescan();
  bool CheckTunnel();
  bool Unpin();  // = SetMode("best")
  bool ForgetToken();
  bool SetMode(const std::string& mode);  // "best" | "selected"
  bool SetSwitchOnFailure(bool enabled);
  bool SetPort(int port);
  bool AddFirewallRule();
  bool CheckFirewall();

  std::string StateJson();

  // Routing of the page's POST /api/<action>: returns an HTTP-like status
  // (202 ok, 400 bad request, 404 unknown action, 409 busy / not possible now).
  int HandlePost(const std::string& action,
      const std::string& query,
      const std::string& body);

  // Waits for the running action, then disconnects. Call after the io_context
  // has stopped (or while it still runs).
  void Shutdown();

 private:
  enum class Phase { kNoToken, kScanning, kReady, kConnecting, kConnected };

  bool Run(const std::string& label, std::function<void()> action);
  bool Setup(const std::string& token);            // worker
  bool ConnectTo(std::optional<std::size_t> idx);  // worker
  void Teardown(bool drop_vless);                  // worker
  void SetPhase(Phase phase, const std::string& message = std::string());
  void OnIoc(const std::function<void()>& fn);
  bool StartVless();
  void SaveSettings();
  void SetNotice(const std::string& text);
  void RefreshFirewall();
  std::string ServerName(std::size_t index);

  boost::asio::io_context& ioc_;
  UserspaceStack& stack_;
  SettingsStore& store_;
  const AppOptions options_;
  const AppDeps deps_;

  std::mutex mu_;  // everything below
  Phase phase_ = Phase::kNoToken;
  std::string message_;
  std::string busy_;
  std::string last_check_;
  std::string token_;
  bool remember_ = false;
  bool token_saved_ = false;
  std::string mode_ = "best";
  bool switch_on_failure_ = true;
  int port_ = 10800;
  std::string selected_name_;  // the server the user chose last
  std::string notice_;         // last problem to show on the page
  FirewallStatus firewall_ = FirewallStatus::kUnsupported;
  Uuid uuid_{};
  std::vector<std::string> hosts_;
  std::shared_ptr<ITunnels> tunnels_;
  std::shared_ptr<FailoverController> controller_;
  std::unique_ptr<VlessServer> vless_;
  std::thread worker_;
  bool shut_down_ = false;
};

}  // namespace fptn::vless
