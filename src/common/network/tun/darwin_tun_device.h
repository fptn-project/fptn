/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <arpa/inet.h>  // NOLINT(build/include_order)
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fcntl.h>  // NOLINT(build/include_order)
#include <memory>
#include <net/if.h>       // NOLINT(build/include_order)
#include <net/if_utun.h>  // NOLINT(build/include_order)
#include <string>
#include <sys/ioctl.h>         // NOLINT(build/include_order)
#include <sys/kern_control.h>  // NOLINT(build/include_order)
#include <sys/socket.h>        // NOLINT(build/include_order)
#include <sys/sys_domain.h>    // NOLINT(build/include_order)
#include <unistd.h>            // NOLINT(build/include_order)

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::common::network {

class DarwinTunDevice {
 public:
  DarwinTunDevice() : fd_(-1) {}

  ~DarwinTunDevice() { Close(); }

  DarwinTunDevice(const DarwinTunDevice&) = delete;
  DarwinTunDevice& operator=(const DarwinTunDevice&) = delete;

  bool Open(const std::string& /*requested_name*/) {
    fd_ = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd_ < 0) {
      SPDLOG_ERROR(
          "DarwinTunDevice: socket(PF_SYSTEM) failed: {}", strerror(errno));
      return false;
    }

    struct ctl_info info = {};
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    if (ioctl(fd_, CTLIOCGINFO, &info) < 0) {
      SPDLOG_ERROR(
          "DarwinTunDevice: ioctl(CTLIOCGINFO) failed: {}", strerror(errno));
      close(fd_);
      fd_ = -1;
      return false;
    }

    // Try utun numbers starting from 0 until we find an available one
    constexpr int kMaxUtunAttempts = 256;
    bool connected = false;
    for (int unit = 0; unit < kMaxUtunAttempts; ++unit) {
      struct sockaddr_ctl addr = {};
      addr.sc_len = sizeof(addr);
      addr.sc_family = AF_SYSTEM;
      addr.ss_sysaddr = AF_SYS_CONTROL;
      addr.sc_id = info.ctl_id;
      addr.sc_unit = unit + 1;  // sc_unit is 1-based (utun0 = unit 1)

      if (connect(fd_, reinterpret_cast<struct sockaddr*>(&addr),
              sizeof(addr)) == 0) {
        connected = true;
        break;
      }
    }

    if (!connected) {
      SPDLOG_ERROR("DarwinTunDevice: failed to connect to any utun device");
      close(fd_);
      fd_ = -1;
      return false;
    }

    // Get the assigned interface name
    char ifname[IFNAMSIZ] = {};
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(
            fd_, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
      SPDLOG_ERROR("DarwinTunDevice: getsockopt(UTUN_OPT_IFNAME) failed: {}",
          strerror(errno));
      close(fd_);
      fd_ = -1;
      return false;
    }
    name_ = ifname;
    SPDLOG_INFO("DarwinTunDevice: opened {}", name_);
    return true;
  }

  void Close() {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }

  // For unit tests: inject a pre-created fd (e.g., from socketpair)
  bool OpenWithFd(int fd, const std::string& name) {
    Close();
    fd_ = fd;
    name_ = name;
    return true;
  }

  [[nodiscard]] const std::string& GetName() const { return name_; }

  bool ConfigureIPv4(const std::string& addr, int mask) {
    // Use ifconfig to set IPv4 address
    const std::string cmd = "ifconfig " + name_ + " inet " + addr + "/" +
                            std::to_string(mask) + " " + addr;
    SPDLOG_DEBUG("DarwinTunDevice: {}", cmd);
    return system(cmd.c_str()) == 0;  // NOLINT(cert-env33-c)
  }

  bool ConfigureIPv6(const std::string& addr, int mask) {
    const std::string cmd =
        "ifconfig " + name_ + " inet6 " + addr + "/" + std::to_string(mask);
    SPDLOG_DEBUG("DarwinTunDevice: {}", cmd);
    return system(cmd.c_str()) == 0;  // NOLINT(cert-env33-c)
  }

  void SetNonBlocking(bool enabled) {
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0) {
      return;
    }
    if (enabled) {
      flags |= O_NONBLOCK;
    } else {
      flags &= ~O_NONBLOCK;
    }
    fcntl(fd_, F_SETFL, flags);
  }

  void SetMTU(int mtu) {
    const std::string cmd = "ifconfig " + name_ + " mtu " + std::to_string(mtu);
    system(cmd.c_str());  // NOLINT(cert-env33-c)
  }

  void BringUp() {
    const std::string cmd = "ifconfig " + name_ + " up";
    system(cmd.c_str());  // NOLINT(cert-env33-c)
  }

  int Read(void* buffer, int size) {
    // macOS utun prepends a 4-byte protocol family header
    constexpr int kAfHeaderSize = 4;
    const int total_size = size + kAfHeaderSize;

    EnsureReadBuffer(total_size);

    const ssize_t n = ::read(fd_, read_buf_.get(), total_size);
    if (n <= kAfHeaderSize) {
      return 0;
    }

    const int payload_size = static_cast<int>(n) - kAfHeaderSize;
    std::memcpy(buffer, read_buf_.get() + kAfHeaderSize, payload_size);
    return payload_size;
  }

  int Write(const void* data, int size) {
    // Determine address family from IP version nibble
    constexpr int kAfHeaderSize = 4;
    const auto* pkt = static_cast<const std::uint8_t*>(data);
    const std::uint8_t version = (pkt[0] >> 4) & 0x0F;

    std::uint32_t af_header = 0;
    if (version == 4) {
      af_header = htonl(AF_INET);
    } else if (version == 6) {
      af_header = htonl(AF_INET6);
    } else {
      return 0;
    }

    const int total_size = kAfHeaderSize + size;
    EnsureWriteBuffer(total_size);

    std::memcpy(write_buf_.get(), &af_header, kAfHeaderSize);
    std::memcpy(write_buf_.get() + kAfHeaderSize, data, size);

    const ssize_t written = ::write(fd_, write_buf_.get(), total_size);
    if (written <= kAfHeaderSize) {
      return 0;
    }
    return static_cast<int>(written) - kAfHeaderSize;
  }

  // cppcheck-suppress functionStatic
  void SetStopFlag(const std::atomic<bool>* /*running*/) {}

 private:
  void EnsureReadBuffer(int size) {
    if (read_buf_size_ < size) {
      read_buf_ = std::make_unique<std::uint8_t[]>(size);
      read_buf_size_ = size;
    }
  }

  void EnsureWriteBuffer(int size) {
    if (write_buf_size_ < size) {
      write_buf_ = std::make_unique<std::uint8_t[]>(size);
      write_buf_size_ = size;
    }
  }

  int fd_;
  std::string name_;

  std::unique_ptr<std::uint8_t[]> read_buf_;
  int read_buf_size_ = 0;
  std::unique_ptr<std::uint8_t[]> write_buf_;
  int write_buf_size_ = 0;
};

}  // namespace fptn::common::network
