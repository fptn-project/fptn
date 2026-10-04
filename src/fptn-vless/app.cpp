#include "fptn-vless/app.h"

#include <algorithm>
#include <cctype>
#include <future>
#include <utility>

#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

#include "fptn-vless/events.h"

namespace fptn::vless {

std::string CleanToken(const std::string& raw) {
  std::string token;
  for (const unsigned char c : raw) {
    if (std::isspace(c) == 0 && c != '"' && c != '\'') {
      token.push_back(static_cast<char>(c));
    }
  }
  return token;
}

Uuid DeriveUuid(const std::string& token) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(token.data()), token.size(),
      digest);
  Uuid uuid{};
  std::copy(digest, digest + 16, uuid.begin());
  uuid[6] = (uuid[6] & 0x0F) | 0x50;
  uuid[8] = (uuid[8] & 0x3F) | 0x80;
  return uuid;
}

namespace {

std::string PercentEncode(const std::string& text) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (const unsigned char c : text) {
    if (std::isalnum(c) != 0 || c == '-' || c == '.' || c == '_' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0F]);
    }
  }
  return out;
}

std::string Lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return text;
}

const char* PhaseName(int phase) {
  static const char* kNames[] = {
      "no_token", "scanning", "ready", "connecting", "connected"};
  return kNames[phase];
}

}  // namespace

std::string MakeLink(const Uuid& uuid, const std::string& host, int port) {
  return fmt::format(
      "vless://{}@{}:{}?encryption=none&security=none&type=tcp&headerType=none"
      "#{}",
      UuidToString(uuid), host, port, PercentEncode("fptn-vless"));
}

App::App(boost::asio::io_context& ioc,
    UserspaceStack& stack,
    SettingsStore& store,
    AppOptions options,
    AppDeps deps)
    : ioc_(ioc),
      stack_(stack),
      store_(store),
      options_(std::move(options)),
      deps_(std::move(deps)) {}

App::~App() { Shutdown(); }

void App::SetPhase(Phase phase, const std::string& message) {
  const std::lock_guard<std::mutex> lock(mu_);
  phase_ = phase;
  message_ = message;
}

// Runs `fn` on the io_context thread and waits (asio objects are not thread
// safe). If the io_context is not running any more we are the only thread.
void App::OnIoc(const std::function<void()>& fn) {
  if (ioc_.stopped()) {
    fn();
    return;
  }
  auto done = std::make_shared<std::promise<void>>();
  auto finished = done->get_future();
  boost::asio::post(ioc_, [fn, done]() {
    fn();
    done->set_value();
  });
  if (finished.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
    SPDLOG_WARN("app: the network loop did not answer in time");
  }
}

bool App::Run(const std::string& label, std::function<void()> action) {
  std::thread finished;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (shut_down_ || !busy_.empty()) {
      return false;
    }
    finished = std::move(worker_);  // the previous action is done
    busy_ = label;
    notice_.clear();
  }
  if (finished.joinable()) {
    finished.join();
  }
  std::thread worker([this, action = std::move(action)]() {
    try {
      action();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("app action failed: {}", ex.what());
    } catch (...) {
      SPDLOG_ERROR("app action failed");
    }
    const std::lock_guard<std::mutex> lock(mu_);
    busy_.clear();
  });
  const std::lock_guard<std::mutex> lock(mu_);
  worker_ = std::move(worker);
  return true;
}

void App::Start(const std::optional<std::string>& cli_token) {
  const Settings saved = store_.Load();
  std::string token = cli_token ? CleanToken(*cli_token) : saved.token;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    token_saved_ = !saved.token.empty();
    remember_ = token_saved_;
    mode_ = saved.mode;
    switch_on_failure_ = saved.switch_on_failure;
    selected_name_ = saved.server;
    port_ = saved.port > 0 ? saved.port : options_.port;
    if (!options_.preferred_server.empty()) {  // --server wins
      mode_ = "selected";
      selected_name_ = options_.preferred_server;
    }
  }
  if (token.empty()) {
    SetPhase(Phase::kNoToken);
    return;
  }
  Run("Подключение...", [this, token]() {
    if (!Setup(token)) {
      return;
    }
    std::optional<std::size_t> index;
    std::string wanted;
    bool selected = false;
    std::shared_ptr<ITunnels> tunnels;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      tunnels = tunnels_;
      wanted = selected_name_;
      selected = mode_ == "selected";
    }
    if (selected && !wanted.empty()) {
      const auto names = tunnels->Names();
      for (std::size_t i = 0; i < names.size(); ++i) {
        if (Lower(names[i]) == Lower(wanted)) {
          index = i;
        }
      }
    }
    ConnectTo(index);
  });
}

void App::Teardown(bool drop_vless) {
  std::shared_ptr<FailoverController> controller;
  std::shared_ptr<ITunnels> tunnels;
  std::unique_ptr<VlessServer> vless;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = std::move(controller_);
    tunnels = std::move(tunnels_);
    if (drop_vless) {
      vless = std::move(vless_);
    }
  }
  if (controller) {
    controller->Stop();
  }
  if (tunnels) {
    tunnels->Shutdown();
  }
  if (vless) {
    OnIoc([&vless]() {
      vless->Stop();
      vless.reset();
    });
  }
}

bool App::Setup(const std::string& token) {
  Teardown(true);
  SetPhase(Phase::kScanning, "Разбор токена...");
  std::shared_ptr<ITunnels> tunnels;
  try {
    tunnels = deps_.make_tunnels(token);
  } catch (const std::exception& ex) {
    Notify("Токен не принят: {}", ex.what());
    SetPhase(Phase::kNoToken, std::string("Токен не принят: ") + ex.what());
    return false;
  }
  if (!tunnels || tunnels->Names().empty()) {
    SetPhase(Phase::kNoToken, "В токене нет серверов");
    return false;
  }
  SetPhase(Phase::kScanning, "Замер отклика серверов...");
  FailoverController::Hooks hooks;
  hooks.probe_all = [tunnels]() { return tunnels->ProbeAll(); };
  hooks.connect = [tunnels](std::size_t i) { return tunnels->Connect(i); };
  hooks.tunnel_down = [tunnels]() { return tunnels->IsDown(); };
  hooks.active_works = deps_.carries_traffic;
  auto controller = std::make_shared<FailoverController>(
      tunnels->Names(), options_.failover, std::move(hooks));
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller->SetSwitchOnFailure(switch_on_failure_);
    controller->SetPinned(mode_ == "selected");
  }
  controller->Scan();

  Uuid uuid = DeriveUuid(token);
  if (!options_.uuid_override.empty()) {
    ParseUuid(options_.uuid_override, uuid);
  }
  {
    const std::lock_guard<std::mutex> lock(mu_);
    token_ = token;
    uuid_ = uuid;
    tunnels_ = std::move(tunnels);
    controller_ = std::move(controller);
  }
  SetPhase(Phase::kReady);
  Notify("Серверов в токене: {}", controller_->Snapshot().size());
  return true;
}

bool App::StartVless() {
  Uuid uuid;
  int port = 0;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (vless_) {
      return true;
    }
    uuid = uuid_;
    port = port_;
  }
  VlessServer::Config config;
  config.listen_address = options_.listen;
  config.port = static_cast<std::uint16_t>(port);
  config.uuid = uuid;
  bool ok = false;
  std::unique_ptr<VlessServer> server;
  OnIoc([&]() {
    server = std::make_unique<VlessServer>(ioc_, config, stack_);
    ok = server->Start();
    if (!ok) {
      server.reset();
    }
  });
  if (!ok) {
    return false;
  }
  const std::lock_guard<std::mutex> lock(mu_);
  vless_ = std::move(server);
  return true;
}

bool App::ConnectTo(std::optional<std::size_t> index) {
  std::shared_ptr<FailoverController> controller;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = controller_;
  }
  if (!controller) {
    return false;
  }
  SetPhase(Phase::kConnecting, "Подключение к серверу...");
  if (!controller->Start(index)) {
    SetPhase(Phase::kReady, "Не удалось подключиться ни к одному серверу");
    Notify("Не удалось подключиться ни к одному серверу");
    return false;
  }
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (index) {
      mode_ = "selected";  // the user named a server: stay on it
    }
    controller->SetPinned(mode_ == "selected");
    controller->SetSwitchOnFailure(switch_on_failure_);
  }
  if (!StartVless()) {
    controller->Stop();
    {
      const std::lock_guard<std::mutex> lock(mu_);
      if (tunnels_) {
        tunnels_->Shutdown();
      }
    }
    int port = 0;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      port = port_;
    }
    const std::string text = fmt::format(
        "Порт {} занят или недоступен. Укажите другой порт справа.", port);
    SetPhase(Phase::kReady, text);
    Notify("{}", text);
    return false;
  }

  std::vector<std::string> hosts;
  if (!options_.link_host.empty()) {
    hosts.push_back(options_.link_host);
  } else if (options_.listen != "0.0.0.0") {
    hosts.push_back(options_.listen);
  } else if (deps_.lan_hosts) {
    hosts = deps_.lan_hosts();
  }
  if (hosts.empty()) {
    hosts.push_back("127.0.0.1");
  }
  {
    const std::lock_guard<std::mutex> lock(mu_);
    hosts_ = hosts;
  }
  SetPhase(Phase::kConnected);
  const auto active = controller->Active();
  const auto snapshot = controller->Snapshot();
  if (active && *active < snapshot.size()) {
    {
      const std::lock_guard<std::mutex> lock(mu_);
      selected_name_ = snapshot[*active].name;
    }
    Notify("Подключено: {}", snapshot[*active].name);
    SaveSettings();
  }
  RefreshFirewall();
  if (deps_.full_check) {
    const std::string summary = deps_.full_check();
    {
      const std::lock_guard<std::mutex> lock(mu_);
      last_check_ = summary;
    }
    Notify("{}", summary);
  }
  return true;
}

void App::SaveSettings() {
  Settings settings;
  std::shared_ptr<FailoverController> controller;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (remember_) {
      settings.token = token_;  // the token only if the user allowed it
    }
    settings.server = selected_name_;
    settings.mode = mode_;
    settings.switch_on_failure = switch_on_failure_;
    settings.port = port_;
    controller = controller_;
  }
  if (controller) {
    const auto active = controller->Active();
    const auto snapshot = controller->Snapshot();
    if (active && *active < snapshot.size() && settings.mode == "selected") {
      settings.server = snapshot[*active].name;
    }
  }
  store_.Save(settings);
}

void App::SetNotice(const std::string& text) {
  const std::lock_guard<std::mutex> lock(mu_);
  notice_ = text;
}

void App::RefreshFirewall() {
  if (!deps_.firewall_status) {
    return;
  }
  int port = 0;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    port = port_;
  }
  const FirewallStatus status = deps_.firewall_status(port);
  const std::lock_guard<std::mutex> lock(mu_);
  firewall_ = status;
}

bool App::SubmitToken(const std::string& token, bool remember) {
  const std::string clean = CleanToken(token);
  if (clean.empty()) {
    return false;
  }
  return Run("Разбор токена...", [this, clean, remember]() {
    if (!Setup(clean)) {
      return;
    }
    {
      const std::lock_guard<std::mutex> lock(mu_);
      remember_ = remember;
      token_saved_ = remember;
    }
    SaveSettings();
  });
}

bool App::Connect(std::optional<std::size_t> index) {
  std::shared_ptr<FailoverController> controller;
  std::shared_ptr<ITunnels> tunnels;
  bool connected = false;
  std::string mode;
  std::string wanted;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = controller_;
    tunnels = tunnels_;
    connected = phase_ == Phase::kConnected;
    mode = mode_;
    wanted = selected_name_;
  }
  if (!controller) {
    return false;
  }
  if (connected) {  // already connected: this is a manual switch
    if (!index) {
      return false;
    }
    return Run("Переключение на сервер...", [this, controller, index]() {
      if (controller->SwitchTo(*index, true)) {
        const std::string name = ServerName(*index);
        {
          const std::lock_guard<std::mutex> lock(mu_);
          mode_ = "selected";
          selected_name_ = name;
        }
        SaveSettings();
      } else {
        SetNotice("Не удалось подключиться к выбранному серверу");
      }
    });
  }
  if (!index && mode == "selected" && !wanted.empty()) {
    const auto names = tunnels->Names();  // "connect" in the selected mode
    for (std::size_t i = 0; i < names.size(); ++i) {
      if (Lower(names[i]) == Lower(wanted)) {
        index = i;
      }
    }
  }
  return Run("Подключение...", [this, index]() { ConnectTo(index); });
}

std::string App::ServerName(std::size_t index) {
  std::shared_ptr<FailoverController> controller;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = controller_;
  }
  if (controller) {
    const auto snapshot = controller->Snapshot();
    if (index < snapshot.size()) {
      return snapshot[index].name;
    }
  }
  return {};
}

bool App::Disconnect() {
  return Run("Отключение...", [this]() {
    std::shared_ptr<FailoverController> controller;
    std::shared_ptr<ITunnels> tunnels;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      controller = controller_;
      tunnels = tunnels_;
    }
    if (controller) {
      controller->Stop();
    }
    if (tunnels) {
      tunnels->Shutdown();
    }
    SetPhase(Phase::kReady);
    Notify("Отключено");
  });
}

bool App::Rescan() {
  std::shared_ptr<FailoverController> controller;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = controller_;
  }
  if (!controller) {
    return false;
  }
  return Run("Замер серверов...", [controller]() { controller->Scan(); });
}

bool App::CheckTunnel() {
  if (!deps_.full_check) {
    return false;
  }
  return Run("Проверка туннеля...", [this]() {
    const std::string summary = deps_.full_check();
    {
      const std::lock_guard<std::mutex> lock(mu_);
      last_check_ = summary;
    }
    Notify("{}", summary);
  });
}

bool App::Unpin() { return SetMode("best"); }

bool App::SetMode(const std::string& mode) {
  if (mode != "best" && mode != "selected") {
    return false;
  }
  std::shared_ptr<FailoverController> controller;
  bool connected = false;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    mode_ = mode;
    controller = controller_;
    connected = phase_ == Phase::kConnected;
  }
  if (controller) {
    controller->SetPinned(mode == "selected");
  }
  SaveSettings();
  if (mode == "best" && connected && controller) {
    // Do not wait for the next periodic scan: look for a better server now.
    return Run("Поиск лучшего сервера...", [controller]() {
      controller->Rebalance();
    });
  }
  return true;
}

bool App::SetSwitchOnFailure(bool enabled) {
  std::shared_ptr<FailoverController> controller;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    switch_on_failure_ = enabled;
    controller = controller_;
  }
  if (controller) {
    controller->SetSwitchOnFailure(enabled);
  }
  SaveSettings();
  return true;
}

bool App::SetPort(int port) {
  if (port < 1 || port > 65535 || port == options_.reserved_port) {
    return false;
  }
  return Run("Смена порта...", [this, port]() {
    int old_port = 0;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      old_port = port_;
    }
    if (port == old_port) {
      return;
    }
    bool running = false;
    Uuid uuid;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      running = vless_ != nullptr;
      uuid = uuid_;
    }
    if (running) {
      // Open the new port first; the old one stays if that fails.
      VlessServer::Config config;
      config.listen_address = options_.listen;
      config.port = static_cast<std::uint16_t>(port);
      config.uuid = uuid;
      std::unique_ptr<VlessServer> fresh;
      bool ok = false;
      std::unique_ptr<VlessServer> old;
      {
        const std::lock_guard<std::mutex> lock(mu_);
        old = std::move(vless_);
      }
      OnIoc([&]() {
        if (old) {
          old->Stop();  // free the old port (it may be the same socket range)
        }
        fresh = std::make_unique<VlessServer>(ioc_, config, stack_);
        ok = fresh->Start();
        if (!ok) {
          fresh.reset();
          // go back to the old port
          VlessServer::Config back = config;
          back.port = static_cast<std::uint16_t>(old_port);
          fresh = std::make_unique<VlessServer>(ioc_, back, stack_);
          if (!fresh->Start()) {
            fresh.reset();
          }
        }
        old.reset();
      });
      {
        const std::lock_guard<std::mutex> lock(mu_);
        vless_ = std::move(fresh);
        if (ok) {
          port_ = port;
        }
      }
      if (!ok) {
        SetNotice(fmt::format("Порт {} занят или недоступен, оставлен {}", port,
            old_port));
        return;
      }
    } else {
      const std::lock_guard<std::mutex> lock(mu_);
      port_ = port;
    }
    Notify("Порт VLESS: {}", port);
    SaveSettings();
    RefreshFirewall();
  });
}

bool App::AddFirewallRule() {
  if (!deps_.firewall_add) {
    return false;
  }
  return Run("Открываю порт в брандмауэре...", [this]() {
    int port = 0;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      port = port_;
    }
    const std::string error = deps_.firewall_add(port);
    if (!error.empty()) {
      SetNotice("Брандмауэр: " + error);
      Notify("Брандмауэр: {}", error);
    } else {
      Notify("Порт {} открыт в брандмауэре Windows", port);
    }
    RefreshFirewall();
  });
}

bool App::CheckFirewall() {
  if (!deps_.firewall_status) {
    return false;
  }
  return Run("Проверка брандмауэра...", [this]() { RefreshFirewall(); });
}

bool App::ForgetToken() {
  return Run("Забываю токен...", [this]() {
    Teardown(true);
    {
      const std::lock_guard<std::mutex> lock(mu_);
      token_.clear();
      token_saved_ = false;
      remember_ = false;
      hosts_.clear();
      last_check_.clear();
    }
    SaveSettings();  // keeps the preferences, drops the token
    SetPhase(Phase::kNoToken);
    Notify("Токен удалён");
  });
}

int App::HandlePost(const std::string& action,
    const std::string& query,
    const std::string& body) {
  const auto result = [](bool ok) { return ok ? 202 : 409; };
  if (action == "token") {
    if (CleanToken(body).empty()) {
      return 400;
    }
    return result(SubmitToken(body, query.find("remember=1") != std::string::npos));
  }
  if (action == "connect") {
    if (query.find("auto=1") != std::string::npos) {
      return result(Connect(std::nullopt));
    }
    if (query.rfind("i=", 0) != 0 || query.size() < 3 || query.size() > 6 ||
        !std::all_of(query.begin() + 2, query.end(),
            [](unsigned char c) { return std::isdigit(c) != 0; })) {
      return 400;
    }
    return result(Connect(static_cast<std::size_t>(std::stoul(query.substr(2)))));
  }
  const auto value = [&query]() {
    return query.rfind("value=", 0) == 0 ? query.substr(6) : std::string();
  };
  if (action == "mode") {
    const std::string v = value();
    return (v == "best" || v == "selected") ? result(SetMode(v)) : 400;
  }
  if (action == "onfail") {
    const std::string v = value();
    return (v == "switch" || v == "nothing") ? result(SetSwitchOnFailure(v == "switch")) : 400;
  }
  if (action == "port") {
    const std::string v = value();
    if (v.empty() || v.size() > 5 ||
        !std::all_of(v.begin(), v.end(),
            [](unsigned char c) { return std::isdigit(c) != 0; })) {
      return 400;
    }
    const int port = std::stoi(v);
    return (port >= 1 && port <= 65535 && port != options_.reserved_port)
               ? result(SetPort(port))
               : 400;
  }
  if (action == "firewall") return result(AddFirewallRule());
  if (action == "firewall_check") return result(CheckFirewall());
  if (action == "disconnect") return result(Disconnect());
  if (action == "rescan") return result(Rescan());
  if (action == "check") return result(CheckTunnel());
  if (action == "unpin") return result(Unpin());
  if (action == "forget") return result(ForgetToken());
  return 404;
}

std::string App::StateJson() {
  nlohmann::json state;
  std::shared_ptr<FailoverController> controller;
  std::shared_ptr<ITunnels> tunnels;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    controller = controller_;
    tunnels = tunnels_;
    state["phase"] = PhaseName(static_cast<int>(phase_));
    state["message"] = message_;
    state["busy"] = busy_;
    state["check"] = last_check_;
    state["token_saved"] = token_saved_;
    state["uuid"] = UuidToString(uuid_);
    state["port"] = port_;
    state["mode"] = mode_;
    state["switch_on_failure"] = switch_on_failure_;
    state["selected"] = selected_name_;
    state["notice"] = notice_;
    state["reserved_port"] = options_.reserved_port;
    static const char* const kFirewall[] = {"unsupported", "unknown", "open", "closed"};
    state["firewall"] = kFirewall[static_cast<int>(firewall_)];
    auto& links = state["links"] = nlohmann::json::array();
    for (const auto& host : hosts_) {
      links.push_back({{"host", host}, {"url", MakeLink(uuid_, host, port_)}});
    }
  }
  auto& servers = state["servers"] = nlohmann::json::array();
  int active_index = -1;
  bool pinned = false;
  if (controller) {
    for (const auto& s : controller->Snapshot()) {
      servers.push_back({{"name", s.name}, {"probed", s.probed},
          {"ping", s.last_ping ? nlohmann::json(*s.last_ping)
                               : nlohmann::json(nullptr)}});
    }
    if (const auto active = controller->Active()) {
      active_index = static_cast<int>(*active);
    }
    pinned = controller->Pinned();
  }
  state["active_index"] = active_index;
  state["pinned"] = pinned;
  state["failover_available"] = options_.failover.failover && servers.size() > 1;
  state["failover"] = state["failover_available"];
  state["tunnel_down"] = active_index >= 0 && tunnels && tunnels->IsDown();
  auto events = RecentEvents();
  if (events.size() > 80) {
    events.erase(events.begin(), events.end() - 80);
  }
  state["events"] = events;
  return state.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void App::Shutdown() {
  std::thread finished;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (shut_down_) {
      return;
    }
    shut_down_ = true;
    finished = std::move(worker_);
  }
  if (finished.joinable()) {
    finished.join();  // an unfinished connect must not outlive the objects
  }
  Teardown(true);
}

}  // namespace fptn::vless
