#pragma once

/*
 * Multi-server failover: decides WHEN to leave the current FPTN server and
 * WHICH one to move to. Deliberately free of any FPTN/network types: probing,
 * connecting and health checks come in as callbacks (Hooks), so the whole
 * policy can be tested without a server.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace fptn::vless {

// Response time in ms; nullopt = no answer.
using PingMs = std::optional<std::uint32_t>;

struct ServerHealth {
  std::string name;
  PingMs last_ping;
  int consecutive_failures = 0;
  bool probed = false;
};

struct SwitchPolicy {
  // The active server is "slow" only if it is BOTH this many times slower than
  // the best one AND slower by at least margin_ms. Without the margin a 40 ms
  // vs 70 ms difference would make us flap between servers.
  double ratio = 1.5;
  std::uint32_t margin_ms = 150;
  // Missed probes in a row before the active server counts as dead (one lost
  // probe is not enough: it is re-checked after Options::confirm_delay).
  int failures_to_drop = 2;
};

struct Decision {
  bool do_switch = false;
  std::size_t target = 0;
  std::string reason;
};

// Pure function. `tunnel_down` = the live tunnel itself reports a lost
// connection (independent of the probe results).
Decision Decide(const SwitchPolicy& policy,
    const std::vector<ServerHealth>& servers,
    std::optional<std::size_t> active,
    bool tunnel_down);

// Order in which servers are tried: `preferred` first, then answering servers
// by ping, then the silent ones (their API probe may be blocked while the
// login still works). `skip` is left out.
std::vector<std::size_t> ConnectOrder(const std::vector<ServerHealth>& servers,
    std::optional<std::size_t> preferred,
    std::optional<std::size_t> skip = std::nullopt);

class FailoverController {
 public:
  using Ms = std::chrono::milliseconds;

  struct Options {
    bool failover = true;     // false: connect once, never switch
    Ms scan_interval{300000};  // 5 min; 0 = no periodic scans
    Ms confirm_delay{30000};   // re-probe after the active server missed one
    Ms down_grace{20000};      // tunnel must stay down this long to fail over
    Ms min_switch_gap{20000};  // never switch more often than this
    Ms tick{1000};
    SwitchPolicy policy;
  };

  struct Hooks {
    // Probe every server; result i belongs to server i. Blocking.
    std::function<std::vector<PingMs>()> probe_all;
    // Make server i the active one. MUST keep the previous tunnel working if
    // it returns false (prepare the new tunnel first, swap afterwards).
    std::function<bool(std::size_t)> connect;
    // The active tunnel has lost its connection.
    std::function<bool()> tunnel_down;
    // Optional. Real traffic check of the active tunnel. Probes of the test
    // file are flaky through some bypass methods, so before leaving a server
    // only because its probes were missed, ask whether it still carries data.
    std::function<bool()> active_works;
  };

  FailoverController(
      std::vector<std::string> names, Options options, Hooks hooks);
  ~FailoverController();
  FailoverController(const FailoverController&) = delete;
  FailoverController& operator=(const FailoverController&) = delete;

  // Probes all servers now and stores the result.
  std::vector<ServerHealth> Scan();
  // Initial connection (uses the last Scan() if it is fresh), then starts the
  // background monitor. False if no server could be connected.
  bool Start(std::optional<std::size_t> preferred = std::nullopt);
  void Stop();

  // The user picked a server: switch now. `pin` = stay on it even when
  // another one is faster; only a dead connection moves us away.
  bool SwitchTo(std::size_t index, bool pin);
  // Re-measures and moves to a clearly better server if there is one (same
  // hysteresis as the periodic scan). True if it switched.
  bool Rebalance();
  void SetPinned(bool pinned) { pinned_ = pinned; }
  bool Pinned() const { return pinned_; }
  // What to do when the current server stops working: move to another one
  // (default) or stay and wait. Ping-based moves are controlled by pinning.
  void SetSwitchOnFailure(bool enabled) { switch_on_failure_ = enabled; }
  bool SwitchOnFailure() const { return switch_on_failure_; }

  std::optional<std::size_t> Active() const;
  std::vector<ServerHealth> Snapshot() const;

 private:
  using Clock = std::chrono::steady_clock;

  void Loop();
  bool TrySwitch(std::size_t target, const std::string& reason);
  void FailOver(const std::string& reason);
  void ApplyScan(const std::vector<PingMs>& results);
  std::string Describe(std::size_t index) const;

  const Options options_;
  const Hooks hooks_;

  mutable std::mutex mu_;  // guards servers_, active_, last_scan_, last_switch_
  std::vector<ServerHealth> servers_;
  std::optional<std::size_t> active_;
  Clock::time_point last_scan_{};
  Clock::time_point last_switch_{};
  bool scanned_ = false;

  std::mutex op_mu_;  // serialises Scan / connect / switch operations
  std::mutex wake_mu_;
  std::condition_variable wake_cv_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> pinned_{false};
  std::atomic<bool> switch_on_failure_{true};
  std::thread thread_;
};

}  // namespace fptn::vless
