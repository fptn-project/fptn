#pragma once

/*
 * "TUN device" that is not a TUN device: packets go to / come from the
 * userspace lwIP stack instead of an OS adapter. Selected at compile time by
 * FPTN_USERSPACE_TUN (see common/network/net_interface.h).
 *
 * Satisfies the duck-typed Device concept of GenericTunInterface. Everything
 * that would touch the OS (adapter creation, IP/MTU configuration, routes) is
 * deliberately a no-op, which is the whole point of this fork.
 */

#include <atomic>
#include <string>

#include "fptn-vless/userspace_stack.h"

namespace fptn::common::network {

class UserspaceTunDevice {
 public:
  // The stack is configured and started by main() before VpnManager::Start().
  bool Open(const std::string& name) {
    name_ = name;
    return fptn::vless::UserspaceStack::Instance().IsRunning();
  }
  void Close() {}
  [[nodiscard]] const std::string& GetName() const { return name_; }

  bool ConfigureIPv4(const std::string&, int) { return true; }
  bool ConfigureIPv6(const std::string&, int) { return true; }
  void SetNonBlocking(bool) {}
  void SetMTU(int) {}
  bool BringUp() { return true; }
  void SetStopFlag(const std::atomic<bool>*) {}

  // Packets lwIP wants to send towards the FPTN server. Waits up to 2 ms,
  // returns 0 when there is nothing (same contract as the Wintun device).
  int Read(void* buffer, int size) {
    return fptn::vless::UserspaceStack::Instance().TakeOutput(
        static_cast<std::uint8_t*>(buffer), static_cast<std::size_t>(size), 2);
  }

  // Packets that arrived from the FPTN server, destined to lwIP.
  int Write(const void* data, int size) {
    if (data == nullptr || size <= 0) {
      return 0;
    }
    fptn::vless::UserspaceStack::Instance().Input(
        static_cast<const std::uint8_t*>(data), static_cast<std::size_t>(size));
    return size;
  }

 private:
  std::string name_;
};

}  // namespace fptn::common::network
