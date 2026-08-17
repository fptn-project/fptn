/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <linux/if_tun.h>  // NOLINT(build/include_order)
#include <memory>
#include <string>
#include <sys/ioctl.h>  // NOLINT(build/include_order)
#include <tuntap++.hh>  // NOLINT(build/include_order)

namespace fptn::common::network {

class LinuxTunDevice {
 public:
  bool Open(const std::string& name) {
    tun_ = std::make_unique<tuntap::tun>();
    tun_->name(name);
    name_ = tun_->name();
    DisableKernelMessages();
    return true;
  }

  void Close() {
    if (tun_) {
      tun_->nonblocking(true);
      tun_.reset();
    }
  }

  [[nodiscard]] const std::string& GetName() const { return name_; }

  bool ConfigureIPv4(const std::string& addr, int mask) const {
    tun_->ip(addr, mask);
    return true;
  }

  bool ConfigureIPv6(const std::string& addr, int mask) const {
    tun_->ip(addr, mask);
    return true;
  }

  void SetNonBlocking(bool enabled) const { tun_->nonblocking(enabled); }

  void SetMTU(int mtu) const { tun_->mtu(mtu); }

  bool BringUp() const {
    tun_->up();
    return true;
  }

  int Read(void* buffer, int size) const {
    for (int i = 0; i < 4; i++) {
      const int res = tun_->read(buffer, static_cast<std::size_t>(size));
      if (res > 0) {
        return res;
      }
    }
    return 0;
  }

  int Write(const void* data, int size) const {
    return tun_->write(const_cast<void*>(data), static_cast<std::size_t>(size));
  }

  // cppcheck-suppress functionStatic
  static void SetStopFlag(const std::atomic<bool>* /*running*/) {}

 protected:
  void DisableKernelMessages() const {
    const int fd = tun_->native_handle();
    if (fd >= 0) {
      ::ioctl(fd, TUNSETDEBUG, 0);
    }
  }

 private:
  std::unique_ptr<tuntap::tun> tun_;
  std::string name_;
};

}  // namespace fptn::common::network
