#pragma once

/*
 * "Does the tunnel actually carry traffic?" Two probes through the userspace
 * stack: a TCP connection to a public IP (routing/NAT) and one to a host name
 * (DNS). The result tells which part is broken when sites do not open.
 */

#include <cstdint>
#include <optional>
#include <string>

#include "fptn-vless/userspace_stack.h"

namespace fptn::vless {

struct TunnelCheckResult {
  std::optional<int> by_ip_ms;    // TCP connect to 1.1.1.1:443
  std::optional<int> by_name_ms;  // DNS + TCP connect to example.com:443
  std::uint64_t packets_out = 0;  // IP packets given to the tunnel
  std::uint64_t packets_in = 0;   // IP packets received from it

  [[nodiscard]] bool Ok() const { return by_ip_ms && by_name_ms; }
  [[nodiscard]] std::string Summary() const;
};

TunnelCheckResult CheckTunnel(UserspaceStack& stack, int timeout_sec = 8);

// Quick yes/no: can a TCP connection to a public IP be opened through it?
bool TunnelCarriesTraffic(UserspaceStack& stack, int timeout_sec = 6);

}  // namespace fptn::vless
