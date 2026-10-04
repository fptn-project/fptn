#include "fptn-vless/failover.h"

#include <algorithm>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-vless/events.h"

namespace fptn::vless {

namespace {

constexpr auto kFreshScan = std::chrono::seconds(60);

// Fastest answering server, optionally ignoring one index.
std::optional<std::size_t> Best(const std::vector<ServerHealth>& servers,
    std::optional<std::size_t> skip) {
  std::optional<std::size_t> best;
  for (std::size_t i = 0; i < servers.size(); ++i) {
    if ((skip && *skip == i) || !servers[i].last_ping) {
      continue;
    }
    if (!best || *servers[i].last_ping < *servers[*best].last_ping) {
      best = i;
    }
  }
  return best;
}

}  // namespace

Decision Decide(const SwitchPolicy& policy,
    const std::vector<ServerHealth>& servers,
    std::optional<std::size_t> active,
    bool tunnel_down) {
  Decision decision;
  if (!active || *active >= servers.size()) {
    if (const auto best = Best(servers, std::nullopt)) {
      decision = {true, *best, "no active server"};
    }
    return decision;
  }

  const ServerHealth& current = servers[*active];
  const bool dead = tunnel_down || (current.probed &&
                                       current.consecutive_failures >=
                                           policy.failures_to_drop);
  if (dead) {
    if (const auto best = Best(servers, active)) {
      decision = {true, *best,
          tunnel_down ? "the connection is lost"
                      : "the server does not answer"};
    } else {
      decision.reason = "no other server answers";
    }
    return decision;
  }

  // Alive. A single missed probe is not a verdict: wait for the re-check.
  if (!current.last_ping) {
    return decision;
  }
  const auto best = Best(servers, std::nullopt);
  if (!best || *best == *active) {
    return decision;
  }
  const double cur_ms = *current.last_ping;
  const double best_ms = *servers[*best].last_ping;
  if (cur_ms > best_ms * policy.ratio &&
      cur_ms - best_ms >= static_cast<double>(policy.margin_ms)) {
    decision = {true, *best, "the ping is high"};
  }
  return decision;
}

std::vector<std::size_t> ConnectOrder(const std::vector<ServerHealth>& servers,
    std::optional<std::size_t> preferred,
    std::optional<std::size_t> skip) {
  std::vector<std::size_t> order;
  std::vector<bool> taken(servers.size(), false);
  if (skip && *skip < servers.size()) {
    taken[*skip] = true;
  }
  if (preferred && *preferred < servers.size() && !taken[*preferred]) {
    order.push_back(*preferred);
    taken[*preferred] = true;
  }
  std::vector<std::size_t> answering;
  std::vector<std::size_t> silent;
  for (std::size_t i = 0; i < servers.size(); ++i) {
    if (!taken[i]) {
      (servers[i].last_ping ? answering : silent).push_back(i);
    }
  }
  std::stable_sort(answering.begin(), answering.end(),
      [&servers](std::size_t a, std::size_t b) {
        return *servers[a].last_ping < *servers[b].last_ping;
      });
  order.insert(order.end(), answering.begin(), answering.end());
  order.insert(order.end(), silent.begin(), silent.end());
  return order;
}

/* ------------------------- FailoverController ------------------------- */

FailoverController::FailoverController(
    std::vector<std::string> names, Options options, Hooks hooks)
    : options_(std::move(options)), hooks_(std::move(hooks)) {
  servers_.reserve(names.size());
  for (auto& name : names) {
    ServerHealth health;
    health.name = std::move(name);
    servers_.push_back(std::move(health));
  }
}

FailoverController::~FailoverController() { Stop(); }

std::string FailoverController::Describe(std::size_t index) const {
  const std::lock_guard<std::mutex> lock(mu_);
  if (index >= servers_.size()) {
    return "?";
  }
  const auto& s = servers_[index];
  return s.last_ping ? s.name + " (" + std::to_string(*s.last_ping) + " ms)"
                     : s.name + " (no response)";
}

std::vector<ServerHealth> FailoverController::Snapshot() const {
  const std::lock_guard<std::mutex> lock(mu_);
  return servers_;
}

std::optional<std::size_t> FailoverController::Active() const {
  const std::lock_guard<std::mutex> lock(mu_);
  return active_;
}

void FailoverController::ApplyScan(const std::vector<PingMs>& results) {
  const std::lock_guard<std::mutex> lock(mu_);
  for (std::size_t i = 0; i < servers_.size() && i < results.size(); ++i) {
    servers_[i].probed = true;
    servers_[i].last_ping = results[i];
    servers_[i].consecutive_failures =
        results[i] ? 0 : servers_[i].consecutive_failures + 1;
  }
  last_scan_ = Clock::now();
  scanned_ = true;
}

std::vector<ServerHealth> FailoverController::Scan() {
  const std::lock_guard<std::mutex> op(op_mu_);
  ApplyScan(hooks_.probe_all());
  return Snapshot();
}

bool FailoverController::TrySwitch(
    std::size_t target, const std::string& reason) {
  Notify("Switching to {}: {}", Describe(target), reason);
  const bool ok = hooks_.connect(target);
  const std::lock_guard<std::mutex> lock(mu_);
  last_switch_ = Clock::now();  // failed attempts are rate-limited too
  if (ok) {
    active_ = target;
    Notify("Now connected through {}", servers_[target].name);
  } else {
    Notify("Could not switch to {}", servers_[target].name);
  }
  return ok;
}

bool FailoverController::SwitchTo(std::size_t index, bool pin) {
  const std::lock_guard<std::mutex> op(op_mu_);
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (index >= servers_.size()) {
      return false;
    }
  }
  const bool ok = TrySwitch(index, "chosen by the user");
  if (ok) {
    pinned_ = pin;
  }
  return ok;
}

bool FailoverController::Rebalance() {
  const std::lock_guard<std::mutex> op(op_mu_);
  ApplyScan(hooks_.probe_all());
  const Decision d = Decide(options_.policy, Snapshot(), Active(), false);
  if (d.do_switch && d.reason == "the ping is high") {
    return TrySwitch(d.target, "the fastest server was requested");
  }
  return false;
}

void FailoverController::FailOver(const std::string& reason) {
  const std::lock_guard<std::mutex> op(op_mu_);
  ApplyScan(hooks_.probe_all());
  const auto order = ConnectOrder(Snapshot(), std::nullopt, Active());
  for (const std::size_t index : order) {
    if (stop_) {
      return;
    }
    if (TrySwitch(index, reason)) {
      return;
    }
  }
  Notify("No other server could be reached, staying on the current one");
}

bool FailoverController::Start(std::optional<std::size_t> preferred) {
  Stop();  // may be restarted after Stop(): finish any previous monitor first
  stop_ = false;
  {
    const std::lock_guard<std::mutex> op(op_mu_);
    bool fresh = false;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      fresh = scanned_ && Clock::now() - last_scan_ < kFreshScan;
    }
    if (!fresh) {
      ApplyScan(hooks_.probe_all());
    }
    bool connected = false;
    for (const std::size_t index : ConnectOrder(Snapshot(), preferred)) {
      Notify("Connecting to {}", Describe(index));
      if (hooks_.connect(index)) {
        const std::lock_guard<std::mutex> lock(mu_);
        active_ = index;
        last_switch_ = Clock::now();
        connected = true;
        break;
      }
      Notify("Server {} is not usable, trying the next one",
          Snapshot()[index].name);
    }
    if (!connected) {
      return false;
    }
  }
  // With a single server there is nothing to switch to.
  if (options_.failover && Snapshot().size() > 1) {
    thread_ = std::thread(&FailoverController::Loop, this);
  }
  return true;
}

void FailoverController::Stop() {
  stop_ = true;
  wake_cv_.notify_all();
  if (thread_.joinable()) {
    thread_.join();
  }
  const std::lock_guard<std::mutex> lock(mu_);
  active_.reset();  // after Stop() nothing is connected through us
}

void FailoverController::Loop() {
  const bool periodic = options_.scan_interval.count() > 0;
  const auto next_after = [&](Ms delay) {
    return periodic ? Clock::now() + delay : Clock::time_point::max();
  };
  auto next_scan = next_after(options_.scan_interval);
  std::optional<Clock::time_point> down_since;

  while (!stop_) {
    {
      std::unique_lock<std::mutex> lock(wake_mu_);
      wake_cv_.wait_for(lock, options_.tick, [this]() { return stop_.load(); });
    }
    if (stop_) {
      break;
    }
    const auto now = Clock::now();
    const bool down = hooks_.tunnel_down && hooks_.tunnel_down();
    if (!down) {
      down_since.reset();
    } else if (!down_since) {
      down_since = now;
    }
    bool gap_ok = false;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      gap_ok = now - last_switch_ >= options_.min_switch_gap;
    }

    // 1. The live tunnel lost its connection and did not come back by itself.
    if (down && gap_ok && switch_on_failure_ &&
        now - *down_since >= options_.down_grace) {
      Notify("The connection to the server is lost, looking for another");
      FailOver("the connection is lost");
      down_since = Clock::now();  // give the new tunnel time to come up
      next_scan = next_after(options_.scan_interval);
      continue;
    }

    // 2. Periodic scan: the server stopped answering or its ping got high.
    if (periodic && now >= next_scan) {
      const std::lock_guard<std::mutex> op(op_mu_);
      if (stop_) {
        break;
      }
      ApplyScan(hooks_.probe_all());
      const auto snapshot = Snapshot();
      SPDLOG_INFO("Server scan finished");
      // Loss of the tunnel is handled by branch 1 (it has the grace period).
      const Decision d = Decide(options_.policy, snapshot, Active(), false);
      bool allowed = d.do_switch && gap_ok;
      if (allowed && pinned_ && d.reason == "the ping is high") {
        allowed = false;  // the user chose this server
      }
      if (allowed && !switch_on_failure_ && d.reason != "the ping is high") {
        allowed = false;  // the user asked to stay when the server is dead
      }
      if (allowed && d.reason == "the server does not answer" &&
          hooks_.active_works && hooks_.active_works()) {
        SPDLOG_INFO("Probes of the active server fail but it carries traffic, "
                    "staying");
        allowed = false;
      }
      if (allowed) {
        TrySwitch(d.target, d.reason);
      }
      Ms delay = options_.scan_interval;
      if (const auto a = Active()) {
        const int misses = Snapshot()[*a].consecutive_failures;
        if (misses > 0 && misses < options_.policy.failures_to_drop) {
          delay = options_.confirm_delay;  // re-check before judging
        }
      }
      next_scan = next_after(delay);
    }
  }
}

}  // namespace fptn::vless
