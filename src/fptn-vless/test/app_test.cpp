// The application state machine with a fake set of servers: token entry,
// scanning, connecting, switching, disconnecting, remembering the token.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include "fptn-vless/app.h"

using namespace fptn::vless;
using namespace std::chrono_literals;
namespace asio = boost::asio;
using json = nlohmann::json;

static int g_fail = 0;
#define CHECK(cond, msg)                                         \
  do {                                                           \
    if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fail; }  \
    else { std::printf("  ok:   %s\n", msg); }                    \
  } while (0)

struct FakeWorld {
  std::mutex mu;
  std::vector<PingMs> pings{300u, 50u, std::nullopt, 120u};
  std::vector<std::size_t> connects;
  bool down = false;
  std::atomic<int> delay_ms{0};
};

class FakeTunnels : public ITunnels {
 public:
  explicit FakeTunnels(FakeWorld& w) : w_(w) {}
  std::vector<std::string> Names() const override { return {"Alpha", "Bravo", "Charlie", "Delta"}; }
  std::vector<PingMs> ProbeAll() override {
    std::this_thread::sleep_for(std::chrono::milliseconds(w_.delay_ms.load()));
    const std::lock_guard<std::mutex> l(w_.mu);
    return w_.pings;
  }
  bool Connect(std::size_t i) override {
    const std::lock_guard<std::mutex> l(w_.mu);
    w_.connects.push_back(i);
    return w_.pings[i].has_value();
  }
  bool IsDown() const override { return w_.down; }
  void Shutdown() override {}
 private:
  FakeWorld& w_;
};

static json State(App& app) { return json::parse(app.StateJson()); }
static bool WaitPhase(App& app, const std::string& phase, int ms = 5000) {
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (std::chrono::steady_clock::now() < end) {
    const auto s = State(app);
    if (s["phase"] == phase && s["busy"] == "") return true;
    std::this_thread::sleep_for(20ms);
  }
  return false;
}
static bool PortOpen(int port) {
  asio::io_context io;
  boost::system::error_code ec;
  asio::ip::tcp::socket s(io);
  s.connect({asio::ip::make_address("127.0.0.1"), static_cast<std::uint16_t>(port)}, ec);
  return !ec;
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  auto& stack = UserspaceStack::Instance();
  UserspaceStack::Config sc;
  sc.ipv4 = "10.0.0.1";
  if (!stack.Start(sc)) return 2;

  const auto dir = std::filesystem::temp_directory_path() / "fptn_app_test";
  std::filesystem::remove_all(dir);
  SettingsStore store(dir.string());

  asio::io_context ioc;
  auto guard = asio::make_work_guard(ioc);
  std::thread io([&] { ioc.run(); });

  FakeWorld world;
  AppOptions options;
  options.failover.scan_interval = 0ms;
  options.listen = "127.0.0.1";
  options.port = 18950;
  AppDeps deps;
  deps.make_tunnels = [&](const std::string& token) -> std::unique_ptr<ITunnels> {
    if (token.rfind("fptnb:", 0) != 0) throw std::runtime_error("bad token");
    return std::make_unique<FakeTunnels>(world);
  };
  deps.lan_hosts = []() { return std::vector<std::string>{"192.168.0.10", "10.1.1.1"}; };
  deps.full_check = []() { return std::string("Tunnel check: fake"); };

  {
    App app(ioc, stack, store, options, deps);

    std::puts("[1] first start without a token");
    app.Start(std::nullopt);
    CHECK(WaitPhase(app, "no_token"), "waits for a token");
    CHECK(app.HandlePost("token", "", "  \n ") == 400, "empty token is a bad request");

    std::puts("[2] wrong token");
    CHECK(app.HandlePost("token", "remember=1", "garbage") == 202, "token accepted for processing");
    CHECK(WaitPhase(app, "no_token"), "back to the token form");
    CHECK(State(app)["message"].get<std::string>().find("bad token") != std::string::npos,
        "the reason is shown");

    std::puts("[3] good token (with quotes and line breaks from a paste)");
    CHECK(app.HandlePost("token", "remember=1", "\"fptnb:AAA\n BBB\"") == 202, "accepted");
    CHECK(WaitPhase(app, "ready"), "servers scanned -> ready");
    auto s = State(app);
    CHECK(s["servers"].size() == 4 && s["servers"][1]["ping"] == 50 && s["servers"][2]["ping"].is_null(),
        "four servers with their response times");
    CHECK(store.Load().token == "fptnb:AAABBB", "token remembered (cleaned)");
    CHECK(s["active_index"] == -1 && !PortOpen(options.port), "not connected, no listener yet");

    std::puts("[4] connect to the fastest");
    CHECK(app.HandlePost("connect", "auto=1", "") == 202, "connect started");
    CHECK(WaitPhase(app, "connected"), "connected");
    s = State(app);
    CHECK(s["active_index"] == 1 && s["pinned"] == false, "the fastest server (Bravo), not pinned");
    CHECK(s["links"].size() == 1 && s["links"][0]["url"].get<std::string>().find("@127.0.0.1:18950") != std::string::npos,
        "a fixed --listen address goes into the link");
    CHECK(PortOpen(options.port), "VLESS port is listening");
    CHECK(s["check"] == "Tunnel check: fake", "tunnel check ran");

    std::puts("[5] manual switch");
    CHECK(app.HandlePost("connect", "i=3", "") == 202, "switch to Delta");
    CHECK(WaitPhase(app, "connected"), "still connected");
    s = State(app);
    CHECK(s["active_index"] == 3 && s["pinned"] == true, "Delta, pinned by the user");
    CHECK(store.Load().server == "Delta" && store.Load().mode == "selected", "choice remembered");
    CHECK(app.HandlePost("unpin", "", "") == 202 && State(app)["pinned"] == false, "back to the best-by-ping mode");
    CHECK(WaitPhase(app, "connected"), "re-balancing finished");

    std::puts("[6] busy");
    world.delay_ms = 400;
    CHECK(app.HandlePost("rescan", "", "") == 202, "rescan started");
    CHECK(app.HandlePost("disconnect", "", "") == 409, "second action while busy -> 409");
    CHECK(State(app)["busy"] != "", "state says what is running");
    CHECK(WaitPhase(app, "connected"), "rescan done");
    world.delay_ms = 0;

    std::puts("[7] disconnect");
    CHECK(app.HandlePost("disconnect", "", "") == 202, "disconnect");
    CHECK(WaitPhase(app, "ready"), "ready again");
    s = State(app);
    CHECK(s["active_index"] == -1 && s["servers"].size() == 4, "no active server, list kept");
    CHECK(app.HandlePost("connect", "i=0", "") == 202 && WaitPhase(app, "connected") &&
              State(app)["active_index"] == 0,
        "reconnect to a chosen server works");
    CHECK(app.HandlePost("connect", "i=2", "") == 202 && WaitPhase(app, "connected") &&
              State(app)["active_index"] == 0,
        "a server that does not answer cannot be selected: stays where it was");
    CHECK(app.HandlePost("bogus", "", "") == 404, "unknown action -> 404");
  }

  std::puts("[8] restart: the saved token connects by itself");
  {
    // the last choice was Alpha (pinned by the user in [7])
    App app(ioc, stack, store, options, deps);
    app.Start(std::nullopt);
    CHECK(WaitPhase(app, "connected"), "connected without any input");
    const auto s = State(app);
    CHECK(s["active_index"] == 0 && s["pinned"] == true, "the remembered server, pinned");
    CHECK(s["token_saved"] == true, "token is marked as saved");

    std::puts("[9] forget the token");
    CHECK(app.HandlePost("forget", "", "") == 202, "forget");
    CHECK(WaitPhase(app, "no_token"), "token form again");
    CHECK(store.Load().token.empty(), "nothing left on disk");
    CHECK(!PortOpen(options.port), "the listener is closed");
  }

  std::puts("[10] token not remembered");
  {
    App app(ioc, stack, store, options, deps);
    app.Start(std::nullopt);
    CHECK(WaitPhase(app, "no_token"), "starts empty");
    app.HandlePost("token", "remember=0", "fptnb:ZZZ");
    CHECK(WaitPhase(app, "ready") && store.Load().token.empty(), "works, but nothing is saved");
  }

  std::puts("[11] port already taken");
  {
    asio::io_context other;
    asio::ip::tcp::acceptor taken(other, {asio::ip::make_address("127.0.0.1"), 18950});
    App app(ioc, stack, store, options, deps);
    app.Start(std::string("fptnb:QQQ"));  // from the command line
    CHECK(WaitPhase(app, "ready"), "stays usable");
    CHECK(State(app)["message"].get<std::string>().find("18950") != std::string::npos,
        "the message names the port");
  }

  std::puts("[12] command-line server wins and is kept");
  {
    auto opts = options;
    opts.preferred_server = "delta";
    App app(ioc, stack, store, opts, deps);
    app.Start(std::string("fptnb:QQQ"));
    CHECK(WaitPhase(app, "connected") && State(app)["active_index"] == 3 && State(app)["pinned"] == true,
        "--server Delta (any case) is used and pinned");
  }

  std::puts("[13] listening on the whole LAN: one link per detected address");
  {
    auto opts = options;
    opts.listen = "0.0.0.0";
    opts.port = 18951;
    App app(ioc, stack, store, opts, deps);
    app.Start(std::string("fptnb:QQQ"));
    CHECK(WaitPhase(app, "connected"), "connected");
    const auto s = State(app);
    CHECK(s["links"].size() == 2 && s["links"][0]["host"] == "192.168.0.10", "links for the LAN addresses, best first");
  }

  std::puts("[14] panel settings: mode, behaviour on failure, port, firewall");
  {
    const auto dir2 = std::filesystem::temp_directory_path() / "fptn_app_test2";
    std::filesystem::remove_all(dir2);
    SettingsStore store2(dir2.string());
    auto opts = options;
    opts.port = 18960;
    opts.reserved_port = 18961;
    AppDeps d = deps;
    std::atomic<int> fw_adds{0};
    std::atomic<bool> fw_open{false};
    d.firewall_status = [&](int) { return fw_open ? FirewallStatus::kOpen : FirewallStatus::kClosed; };
    d.firewall_add = [&](int port) -> std::string {
      if (port == 18999) return "denied";
      ++fw_adds;
      fw_open = true;
      return "";
    };
    {
      App app(ioc, stack, store2, opts, d);
      app.Start(std::string("fptnb:KKK"));
      CHECK(WaitPhase(app, "connected"), "connected");
      auto st = State(app);
      CHECK(st["mode"] == "best" && st["switch_on_failure"] == true && st["port"] == 18960,
          "defaults: best mode, switch on failure, given port");
      CHECK(st["firewall"] == "closed", "firewall state reported");

      CHECK(app.HandlePost("mode", "value=nonsense", "") == 400, "bad mode -> 400");
      CHECK(app.HandlePost("mode", "value=selected", "") == 202 && State(app)["pinned"] == true,
          "selected mode pins the current server");
      CHECK(WaitPhase(app, "connected"), "idle");
      CHECK(store2.Load().mode == "selected" && !store2.Load().server.empty(), "mode and server remembered");

      CHECK(app.HandlePost("onfail", "value=nothing", "") == 202 &&
                State(app)["switch_on_failure"] == false && !store2.Load().switch_on_failure,
          "do nothing on failure, remembered");
      CHECK(app.HandlePost("onfail", "value=x", "") == 400, "bad value -> 400");

      CHECK(app.HandlePost("port", "value=abc", "") == 400, "non-numeric port -> 400");
      CHECK(app.HandlePost("port", "value=0", "") == 400 && app.HandlePost("port", "value=70000", "") == 400,
          "out of range -> 400");
      CHECK(app.HandlePost("port", "value=18961", "") == 400, "the panel's own port is refused");
      CHECK(app.HandlePost("port", "value=18962", "") == 202 && WaitPhase(app, "connected"), "port change runs");
      CHECK(State(app)["port"] == 18962 && PortOpen(18962) && !PortOpen(18960), "new port listens, old one is closed");
      CHECK(State(app)["links"][0]["url"].get<std::string>().find(":18962") != std::string::npos,
          "links show the new port");
      CHECK(store2.Load().port == 18962, "port remembered");

      {
        asio::io_context other;
        asio::ip::tcp::acceptor taken(other, {asio::ip::make_address("127.0.0.1"), 18963});
        CHECK(app.HandlePost("port", "value=18963", "") == 202 && WaitPhase(app, "connected"), "busy port tried");
        st = State(app);
        CHECK(st["port"] == 18962 && PortOpen(18962), "old port kept and still listening");
        CHECK(st["notice"].get<std::string>().find("18963") != std::string::npos, "the problem is shown");
      }

      CHECK(app.HandlePost("firewall", "", "") == 202 && WaitPhase(app, "connected"), "firewall button");
      CHECK(fw_adds == 1 && State(app)["firewall"] == "open", "rule added, state is open now");
      CHECK(app.HandlePost("firewall_check", "", "") == 202, "firewall re-check");
      CHECK(WaitPhase(app, "connected"), "idle");
    }
    {
      App app(ioc, stack, store2, opts, d);  // restart: preferences come back
      app.Start(std::nullopt);
      CHECK(WaitPhase(app, "no_token"), "restarted (the token was not remembered)");
      const auto st = State(app);
      CHECK(st["mode"] == "selected" && st["switch_on_failure"] == false && st["port"] == 18962,
          "mode, failure behaviour and port survive a restart");
    }
    std::filesystem::remove_all(dir2);
  }

  std::filesystem::remove_all(dir);
  std::printf("\n%s\n", g_fail ? "FAILED" : "ALL PASSED");
  guard.reset();
  ioc.stop();
  io.join();
  stack.Stop();
  return g_fail ? 1 : 0;
}
