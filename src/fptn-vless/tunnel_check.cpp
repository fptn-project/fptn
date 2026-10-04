#include "fptn-vless/tunnel_check.h"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>

#include <fmt/format.h>  // NOLINT(build/include_order)

namespace fptn::vless {

namespace {

std::optional<int> TryConnect(
    UserspaceStack& stack, Target target, int timeout_sec) {
  auto done = std::make_shared<std::promise<bool>>();
  auto answer = done->get_future();
  auto once = std::make_shared<std::atomic<bool>>(false);
  FlowCallbacks callbacks;
  callbacks.on_connected = [done, once](bool ok) {
    if (!once->exchange(true)) {
      done->set_value(ok);
    }
  };
  callbacks.on_error = [done, once]() {
    if (!once->exchange(true)) {
      done->set_value(false);
    }
  };
  const auto started = std::chrono::steady_clock::now();
  const TcpFlowPtr flow = stack.Connect(std::move(target), std::move(callbacks));
  std::optional<int> result;
  if (answer.wait_for(std::chrono::seconds(timeout_sec)) ==
          std::future_status::ready &&
      answer.get()) {
    result = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
  }
  flow->Close(true);  // RST: nothing was sent, nobody to be polite to
  return result;
}

}  // namespace

TunnelCheckResult CheckTunnel(UserspaceStack& stack, int timeout_sec) {
  TunnelCheckResult result;
  const std::uint64_t out0 = stack.PacketsOut();
  const std::uint64_t in0 = stack.PacketsIn();
  Target by_ip;
  by_ip.is_ipv4 = true;
  by_ip.ipv4_be = 0x01010101;  // 1.1.1.1 (same in either byte order)
  by_ip.port = 443;
  result.by_ip_ms = TryConnect(stack, by_ip, timeout_sec);
  Target by_name;
  by_name.host = "example.com";
  by_name.port = 443;
  result.by_name_ms = TryConnect(stack, by_name, timeout_sec);
  result.packets_out = stack.PacketsOut() - out0;
  result.packets_in = stack.PacketsIn() - in0;
  return result;
}

bool TunnelCarriesTraffic(UserspaceStack& stack, int timeout_sec) {
  for (const std::uint32_t ip : {0x01010101u, 0x08080808u}) {  // 1.1.1.1, 8.8.8.8
    Target by_ip;
    by_ip.is_ipv4 = true;
    by_ip.ipv4_be = ip;
    by_ip.port = 443;
    if (TryConnect(stack, by_ip, timeout_sec / 2).has_value()) {
      return true;
    }
  }
  return false;
}

std::string TunnelCheckResult::Summary() const {
  const auto part = [](const std::optional<int>& ms) {
    return ms ? fmt::format("ok, {} ms", *ms) : std::string("FAILED");
  };
  std::string text = fmt::format("Tunnel check: by IP {}; by name {}",
      part(by_ip_ms), part(by_name_ms));
  if (Ok()) {
    return text;
  }
  text += fmt::format(" (packets to the server: {}, from the server: {})",
      packets_out, packets_in);
  if (!by_ip_ms && packets_out == 0) {
    text += ". Nothing left the program: the stack/tunnel is not working.";
  } else if (!by_ip_ms && packets_in == 0) {
    text += ". The server receives nothing back: it does not answer or "
            "filters this traffic.";
  } else if (by_ip_ms && !by_name_ms) {
    text += ". Internet works but names do not resolve (DNS).";
  }
  return text;
}

}  // namespace fptn::vless
