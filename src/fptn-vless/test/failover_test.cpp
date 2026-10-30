// Tests of the failover policy and controller with a fake "world": pings,
// connect results and tunnel health are scripted, no network, no FPTN server.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "fptn-vless/failover.h"

using namespace fptn::vless;
using namespace std::chrono_literals;

static int g_fail = 0;
#define CHECK(cond, msg)                                         \
  do {                                                           \
    if (!(cond)) {                                               \
      std::printf("  FAIL: %s\n", msg);                          \
      ++g_fail;                                                  \
    } else {                                                     \
      std::printf("  ok:   %s\n", msg);                          \
    }                                                            \
  } while (0)

static bool WaitFor(const std::function<bool()>& pred, int timeout_ms) {
  const auto end = std::chrono::steady_clock::now() +
                   std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < end) {
    if (pred()) return true;
    std::this_thread::sleep_for(5ms);
  }
  return pred();
}

static ServerHealth H(const char* name, PingMs ping, int failures = 0) {
  ServerHealth h;
  h.name = name;
  h.last_ping = ping;
  h.consecutive_failures = failures;
  h.probed = true;
  return h;
}

/* ------------------------------ fake world ------------------------------ */

struct World {
  std::mutex mu;
  std::vector<PingMs> pings;
  std::vector<bool> connectable;
  std::vector<std::size_t> connect_log;
  bool tunnel_down = false;
  int miss_once = -1;  // this server misses exactly one probe
  int probes = 0;

  std::vector<std::size_t> Log() {
    const std::lock_guard<std::mutex> l(mu);
    return connect_log;
  }
  void Set(std::size_t i, PingMs p) {
    const std::lock_guard<std::mutex> l(mu);
    pings[i] = p;
  }
  void SetDown(bool v) {
    const std::lock_guard<std::mutex> l(mu);
    tunnel_down = v;
  }
};

static FailoverController::Hooks MakeHooks(World& w) {
  FailoverController::Hooks hooks;
  hooks.probe_all = [&w]() {
    const std::lock_guard<std::mutex> l(w.mu);
    ++w.probes;
    auto result = w.pings;
    if (w.miss_once >= 0) {
      result[static_cast<std::size_t>(w.miss_once)] = std::nullopt;
      w.miss_once = -1;
    }
    return result;
  };
  hooks.connect = [&w](std::size_t i) {
    const std::lock_guard<std::mutex> l(w.mu);
    w.connect_log.push_back(i);
    if (!w.connectable[i]) return false;
    w.tunnel_down = false;  // a fresh tunnel is healthy
    return true;
  };
  hooks.tunnel_down = [&w]() {
    const std::lock_guard<std::mutex> l(w.mu);
    return w.tunnel_down;
  };
  return hooks;
}

static FailoverController::Options FastOptions() {
  FailoverController::Options o;
  o.scan_interval = 120ms;
  o.confirm_delay = 40ms;
  o.down_grace = 100ms;
  o.min_switch_gap = 30ms;
  o.tick = 10ms;
  return o;
}

static std::vector<std::string> Names(std::size_t n) {
  std::vector<std::string> v;
  for (std::size_t i = 0; i < n; ++i) v.push_back("S" + std::to_string(i));
  return v;
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  const SwitchPolicy p;  // defaults: ratio 1.5, margin 150 ms, 2 misses

  std::puts("[1] Decide(): when to leave the active server");
  {
    auto d = Decide(p, {H("a", 100), H("b", 100)}, 0, false);
    CHECK(!d.do_switch, "equal servers: stay");
    d = Decide(p, {H("a", 100), H("b", 40)}, 0, false);
    CHECK(!d.do_switch, "100 ms vs 40 ms (diff 60 < 150): stay");
    d = Decide(p, {H("a", 200), H("b", 100)}, 0, false);
    CHECK(!d.do_switch, "200 vs 100 (ratio 2 but diff 100 < 150): stay");
    d = Decide(p, {H("a", 400), H("b", 280)}, 0, false);
    CHECK(!d.do_switch, "400 vs 280 (diff 120, ratio 1.43): stay");
    d = Decide(p, {H("a", 400), H("b", 100)}, 0, false);
    CHECK(d.do_switch && d.target == 1, "400 vs 100: switch to the better one");
    d = Decide(p, {H("a", std::nullopt, 1), H("b", 100)}, 0, false);
    CHECK(!d.do_switch, "ONE missed probe is not a verdict: stay");
    d = Decide(p, {H("a", std::nullopt, 2), H("b", 100)}, 0, false);
    CHECK(d.do_switch && d.target == 1, "two missed probes: switch");
    d = Decide(p, {H("a", 50), H("b", 60)}, 0, true);
    CHECK(d.do_switch && d.target == 1, "tunnel down: switch even if probes ok");
    d = Decide(p, {H("a", std::nullopt, 5), H("b", std::nullopt, 5)}, 0, false);
    CHECK(!d.do_switch, "everything dead: nowhere to go, stay");
    d = Decide(p, {H("a", std::nullopt, 2), H("b", 90), H("c", 30)}, 0, false);
    CHECK(d.do_switch && d.target == 2, "dead server: pick the FASTEST other");
    d = Decide(p, {H("a", 10), H("b", 20)}, std::nullopt, false);
    CHECK(d.do_switch && d.target == 0, "no active server: pick the best");
  }

  std::puts("[2] ConnectOrder()");
  {
    auto order = ConnectOrder(
        {H("a", 80), H("b", 40), H("c", std::nullopt), H("d", 60)}, std::nullopt);
    CHECK((order == std::vector<std::size_t>{1, 3, 0, 2}),
        "answering servers by ping, silent ones last");
    order = ConnectOrder(
        {H("a", 80), H("b", 40), H("c", std::nullopt)}, std::size_t{0});
    CHECK((order == std::vector<std::size_t>{0, 1, 2}),
        "preferred server goes first");
    order = ConnectOrder({H("a", 80), H("b", 40), H("c", 50)}, std::nullopt, 1);
    CHECK((order == std::vector<std::size_t>{2, 0}), "skip leaves one out");
  }

  std::puts("[3] controller: initial connection");
  {
    World w;
    w.pings = {80, 40, std::nullopt};
    w.connectable = {true, true, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    CHECK(c.Start() && c.Active() == 1, "connects to the fastest server");
    CHECK((w.Log() == std::vector<std::size_t>{1}), "only one connect call");
  }
  {
    World w;
    w.pings = {80, 40, std::nullopt};
    w.connectable = {true, true, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    CHECK(c.Start(std::size_t{0}) && c.Active() == 0, "user's choice wins");
  }
  {
    World w;
    w.pings = {80, 40, std::nullopt};
    w.connectable = {true, false, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    CHECK(c.Start() && c.Active() == 0, "fastest not usable: next one");
    CHECK((w.Log() == std::vector<std::size_t>{1, 0}), "tried 1 then 0");
  }
  {
    World w;
    w.pings = {80, 40};
    w.connectable = {false, false};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    CHECK(!c.Start(), "no server usable: Start() reports failure");
  }

  std::puts("[4] controller: periodic scan failover");
  {
    World w;
    w.pings = {80, 40, 90};
    w.connectable = {true, true, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    c.Start();
    w.Set(1, std::nullopt);  // the active server dies
    CHECK(WaitFor([&] { return c.Active() == 0; }, 3000),
        "dead active server -> moves to the best remaining one");
    CHECK((w.Log() == std::vector<std::size_t>{1, 0}), "exactly one switch");
  }
  {
    World w;
    w.pings = {80, 40, 90};
    w.connectable = {true, true, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    c.Start();
    {
      const std::lock_guard<std::mutex> l(w.mu);
      w.miss_once = 1;  // one lost probe only
    }
    std::this_thread::sleep_for(900ms);
    CHECK(c.Active() == 1 && w.Log().size() == 1,
        "a single lost probe does not cause a switch");
  }
  {
    World w;
    w.pings = {400, 100};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000),
        "high ping on the active server -> moves to the better one");
  }
  {
    World w;
    w.pings = {120, 100};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    const int before = [&] { const std::lock_guard<std::mutex> l(w.mu); return w.probes; }();
    std::this_thread::sleep_for(900ms);
    const int after = [&] { const std::lock_guard<std::mutex> l(w.mu); return w.probes; }();
    CHECK(after - before >= 4, "several scans really happened");
    CHECK(w.Log().size() == 1, "small ping difference: no flapping");
  }
  {
    World w;
    w.pings = {80, 40};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});  // active = 0 (80 ms); then 1 gets slow too
    w.Set(0, std::nullopt);
    w.Set(1, std::nullopt);
    std::this_thread::sleep_for(900ms);
    CHECK(c.Active() == 0 && w.Log().size() == 1,
        "everything dead: do not hop around, stay put");
  }

  std::puts("[5] controller: lost tunnel");
  {
    World w;
    w.pings = {50, 60, 70};
    w.connectable = {true, true, true};
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    c.Start();
    CHECK(c.Active() == 0, "started on the best");
    w.SetDown(true);  // the tunnel reports a lost connection
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000),
        "tunnel stays down past the grace period -> switch to next best");
    CHECK((w.Log() == std::vector<std::size_t>{0, 1}), "one switch only");
  }
  {
    World w;
    w.pings = {50, 60};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start();
    w.SetDown(true);
    std::this_thread::sleep_for(40ms);
    w.SetDown(false);  // it recovered by itself within the grace period
    std::this_thread::sleep_for(600ms);
    CHECK(c.Active() == 0 && w.Log().size() == 1,
        "short outage that heals itself: no switch");
  }
  {
    World w;
    w.pings = {50, 60, 70};
    w.connectable = {true, false, true};  // next best cannot be connected
    FailoverController c(Names(3), FastOptions(), MakeHooks(w));
    c.Start();
    w.SetDown(true);
    CHECK(WaitFor([&] { return c.Active() == 2; }, 3000),
        "next best unusable -> tries the one after it");
  }

  std::puts("[6] controller: switches off / edge cases");
  {
    World w;
    w.pings = {400, 40};
    w.connectable = {true, true};
    auto o = FastOptions();
    o.failover = false;
    FailoverController c(Names(2), o, MakeHooks(w));
    c.Start(std::size_t{0});
    w.SetDown(true);
    std::this_thread::sleep_for(600ms);
    CHECK(c.Active() == 0 && w.Log().size() == 1, "failover=false: never switches");
  }
  {
    World w;
    w.pings = {50};
    w.connectable = {true};
    FailoverController c(Names(1), FastOptions(), MakeHooks(w));
    CHECK(c.Start() && c.Active() == 0, "single server works");
    w.SetDown(true);
    std::this_thread::sleep_for(300ms);
    CHECK(w.Log().size() == 1, "single server: nothing to switch to");
  }
  {
    World w;
    w.pings = {50, 60};
    w.connectable = {true, true};
    auto o = FastOptions();
    o.tick = 1000ms;  // long tick: Stop() must still be immediate
    FailoverController c(Names(2), o, MakeHooks(w));
    c.Start();
    const auto t0 = std::chrono::steady_clock::now();
    c.Stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 500, "Stop() does not wait for the next tick");
  }

  std::puts("[7] pinned server, traffic check before leaving");
  {
    World w;  // user picked S0 (slow); S1 is much faster
    w.pings = {600, 50};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    c.SetPinned(true);
    std::this_thread::sleep_for(700ms);
    CHECK(c.Active() == 0, "pinned: stays on the slow server the user chose");
    c.SetPinned(false);
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000),
        "unpinned: moves to the faster one");
  }
  {
    World w;  // pinned server dies -> must still leave
    w.pings = {600, 50};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    c.SetPinned(true);
    w.SetDown(true);
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000),
        "pinned but connection lost: still fails over");
  }
  {
    World w;  // probes of S0 fail, but it carries traffic
    w.pings = {std::nullopt, 50};
    w.connectable = {true, true};
    auto hooks = MakeHooks(w);
    hooks.active_works = []() { return true; };
    FailoverController c(Names(2), FastOptions(), hooks);
    c.Start(std::size_t{0});
    std::this_thread::sleep_for(700ms);
    CHECK(c.Active() == 0, "probes missed but traffic works: no switch");
  }
  {
    World w;  // probes fail AND no traffic -> leave
    w.pings = {std::nullopt, 50};
    w.connectable = {true, true};
    auto hooks = MakeHooks(w);
    hooks.active_works = []() { return false; };
    FailoverController c(Names(2), FastOptions(), hooks);
    c.Start(std::size_t{0});
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000),
        "probes missed and no traffic: switches");
  }
  {
    World w;
    w.pings = {400, 40};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    CHECK(c.SwitchTo(1, true) && c.Active() == 1 && c.Pinned(),
        "SwitchTo(): manual switch pins the choice");
    CHECK(!c.SwitchTo(9, true), "SwitchTo(): bad index is refused");
  }

  std::puts("[8] what to do when the server dies");
  {
    World w;
    w.pings = {50, 60};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    c.SetSwitchOnFailure(false);
    w.SetDown(true);
    std::this_thread::sleep_for(700ms);
    CHECK(c.Active() == 0 && w.Log().size() == 1, "'do nothing': stays on a dead server");
    c.SetSwitchOnFailure(true);
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000), "'switch': moves on once enabled");
  }
  {
    World w;  // probes of the active server fail for good
    w.pings = {std::nullopt, 50};
    w.connectable = {true, true};
    auto hooks = MakeHooks(w);
    hooks.active_works = []() { return false; };
    FailoverController c(Names(2), FastOptions(), hooks);
    c.Start(std::size_t{0});
    c.SetSwitchOnFailure(false);
    std::this_thread::sleep_for(700ms);
    CHECK(c.Active() == 0, "'do nothing': a silent server is not abandoned either");
  }
  {
    World w;  // quality-based moves are NOT failures: 'best' mode still follows ping
    w.pings = {600, 50};
    w.connectable = {true, true};
    FailoverController c(Names(2), FastOptions(), MakeHooks(w));
    c.Start(std::size_t{0});
    c.SetSwitchOnFailure(false);
    CHECK(WaitFor([&] { return c.Active() == 1; }, 3000), "'do nothing' does not stop moving to a faster server");
  }

  std::printf("\n%s\n", g_fail ? "FAILED" : "ALL PASSED");
  return g_fail ? 1 : 0;
}
