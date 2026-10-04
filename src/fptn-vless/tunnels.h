#pragma once

/*
 * What the application needs from "a set of FPTN servers". TunnelManager is
 * the real implementation; tests use a fake one.
 */

#include <cstddef>
#include <string>
#include <vector>

#include "fptn-vless/failover.h"

namespace fptn::vless {

class ITunnels {
 public:
  virtual ~ITunnels() = default;
  virtual std::vector<std::string> Names() const = 0;
  virtual std::vector<PingMs> ProbeAll() = 0;
  virtual bool Connect(std::size_t index) = 0;
  virtual bool IsDown() const = 0;
  virtual void Shutdown() = 0;
};

}  // namespace fptn::vless
