/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/data/channel.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

namespace fptn::common::network {
class DataRateCalculator {
 public:
  explicit DataRateCalculator(
      std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
      : interval_(interval),
        bytes_(0),
        lastUpdateTime_(std::chrono::steady_clock::now()),
        rate_(0) {}
  void Update(std::size_t len) noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - lastUpdateTime_;
    bytes_ += len;
    if (elapsed >= interval_) {
      rate_ = static_cast<std::size_t>(bytes_ / elapsed.count());
      lastUpdateTime_ = now;
      bytes_ = 0;
    }
  }
  std::size_t GetRateForSecond() const noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

    const auto interval_count = interval_.count();
    if (interval_count) {
      return static_cast<std::size_t>(rate_ / (1000 / interval_.count()));
    }
    return 0;
  }

 private:
  mutable std::mutex mutex_;
  std::chrono::milliseconds interval_;
  std::atomic<std::size_t> bytes_;
  std::chrono::steady_clock::time_point lastUpdateTime_;
  std::atomic<std::size_t> rate_;
};

using NewIPPacketCallback = std::function<void(IPPacketPtr packet)>;

/**
 * @brief Base network interface class using CRTP (Curiously Recurring Template
 * Pattern)
 *
 * This template provides common interface functionality while delegating
 * platform-specific operations to the derived implementation class.
 *
 * CRTP Benefits:
 *  - Static polymorphism (no virtual function overhead)
 *  - Clear separation of interface and implementation
 *  - Compile-time enforcement of interface contracts
 *
 * Derived classes must implement:
 *  - StartImpl()     - Initialize the interface
 *  - StopImpl()      - Shutdown the interface
 *  - SendImpl()      - Packet transmission
 *  - GetSendRateImpl()    - Outbound rate monitoring
 *  - GetReceiveRateImpl() - Inbound rate monitoring
 */
template <typename Implementation>
class BaseNetInterface {
 public:
  friend Implementation;

  // Network configuration
  struct Config {
    std::string name;
    fptn::common::network::IPv4Address ipv4_addr;
    int ipv4_netmask;
    fptn::common::network::IPv6Address ipv6_addr;
    int ipv6_netmask;
  };

  bool Start() { return impl()->StartImpl(); }

  bool Stop() { return impl()->StopImpl(); }

  bool Send(IPPacketPtr packet) { return impl()->SendImpl(std::move(packet)); }

  std::size_t GetSendRate() { return impl()->GetSendRateImpl(); }

  std::size_t GetReceiveRate() { return impl()->GetReceiveRateImpl(); }

 private:
  explicit BaseNetInterface(Config config)
      : config_(std::move(config)), recv_ip_packet_callback_(nullptr) {}

  Implementation* impl() { return static_cast<Implementation*>(this); }

 public:
  [[nodiscard]] const std::string& Name() const noexcept {
    return config_.name;
  }

  [[nodiscard]] const fptn::common::network::IPv4Address& IPv4Addr()
      const noexcept {
    return config_.ipv4_addr;
  }

  [[nodiscard]] int IPv4Netmask() const noexcept {
    return config_.ipv4_netmask;
  }

  [[nodiscard]] const fptn::common::network::IPv6Address& IPv6Addr()
      const noexcept {
    return config_.ipv6_addr;
  }

  int IPv6Netmask() const noexcept { return config_.ipv6_netmask; }

  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept {
    recv_ip_packet_callback_ = callback;
  }

  [[nodiscard]] NewIPPacketCallback GetRecvIPPacketCallback() const {
    return recv_ip_packet_callback_;
  }

 private:
  Config config_;
  NewIPPacketCallback recv_ip_packet_callback_;
};

/**
 * @brief Generic TUN interface parameterized by a platform-specific Device.
 *
 * The Device type must satisfy the following concept (duck-typed):
 *   bool Open(const std::string& name);
 *   void Close();
 *   std::string GetName() const;
 *   bool ConfigureIPv4(const std::string& addr, int mask);
 *   bool ConfigureIPv6(const std::string& addr, int mask);
 *   void SetNonBlocking(bool enabled);
 *   void SetMTU(int mtu);
 *   void BringUp();
 *   int  Read(void* buffer, int size);
 *   int  Write(const void* data, int size);
 *   void SetStopFlag(const std::atomic<bool>* running);
 *
 * Platform-specific devices: LinuxTunDevice, DarwinTunDevice, WinTunDevice
 */
template <typename Device>
class GenericTunInterface final
    : public BaseNetInterface<GenericTunInterface<Device>> {
 public:
  using Base = BaseNetInterface<GenericTunInterface<Device>>;
  friend Base;

  using Config = typename Base::Config;

  explicit GenericTunInterface(Config config)
      : Base(std::move(config)), mtu_(FPTN_MTU_SIZE), running_(false) {}

  ~GenericTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() noexcept {
    const std::scoped_lock lock(mutex_);

    try {
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.Open(this->Name())) {
        SPDLOG_ERROR("Failed to open TUN device");
        return false;
      }
      // Update name to actual device name (may differ, e.g., utun on macOS)
      this->config_.name = device_.GetName();

      /* set IPv6 */
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.ConfigureIPv6(
              this->IPv6Addr().ToString(), this->IPv6Netmask())) {
        SPDLOG_WARN("IPv6 configuration failed, continuing with IPv4 only");
      }
      /* set IPv4 */
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.ConfigureIPv4(
              this->IPv4Addr().ToString(), this->IPv4Netmask())) {
        SPDLOG_ERROR("IPv4 configuration failed");
        device_.Close();
        return false;
      }
      device_.SetNonBlocking(true);
      device_.SetMTU(mtu_);
      device_.BringUp();

      running_ = true;
      device_.SetStopFlag(&running_);
      thread_ = std::thread(&GenericTunInterface::Run, this);
      return thread_.joinable();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("Error start: {}", ex.what());
    }
    return false;
  }

  bool StopImpl() noexcept {
    if (!running_) {
      return false;
    }

    const std::scoped_lock lock(mutex_);

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {  // Double-check after acquiring lock
      return false;
    }

    if (thread_.joinable()) {
      running_ = false;
      thread_.join();
      device_.Close();
    }
    return true;
  }

  bool SendImpl(IPPacketPtr packet) noexcept {
    if (!running_ || !packet || !packet->Size()) {
      return false;
    }

    try {
      const std::scoped_lock lock(mutex_);

      if (running_) {
        const auto* raw_packet = packet->GetRawPacket();
        if (!raw_packet) {
          return false;
        }
        const auto* data = raw_packet->getRawData();
        const auto len = raw_packet->getRawDataLen();

        const int bytes_written = device_.Write(data, static_cast<int>(len));

        send_rate_calculator_.Update(bytes_written);

        return bytes_written == len;
      }
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("SendImpl error: {}", ex.what());
    }
    return false;
  }

  std::size_t GetSendRateImpl() const noexcept {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRateImpl() const noexcept {
    return receive_rate_calculator_.GetRateForSecond();
  }

 private:
  void Run() {
    const auto callback = this->GetRecvIPPacketCallback();
    while (running_) {
      std::vector<std::uint8_t> buffer(mtu_);
      const int size = device_.Read(buffer.data(), mtu_);
      if (size > 0 && running_) {
        auto packet = IPPacket::Parse(buffer, size);
        if (running_ && packet != nullptr && callback) {
          receive_rate_calculator_.Update(packet->Size());  // calculate rate
          callback(std::move(packet));
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  mutable std::mutex mutex_;

  const std::uint16_t mtu_;

  std::atomic<bool> running_;
  std::thread thread_;
  Device device_;
  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;
};

}  // namespace fptn::common::network

// Platform-specific TUN device includes (outside namespace to avoid nesting)
#if defined(__APPLE__)
#include "common/network/tun/darwin_tun_device.h"
#elif defined(__linux__)
#include "common/network/tun/linux_tun_device.h"
#elif defined(_WIN32)
#include "common/network/tun/win_tun_device.h"
#endif

namespace fptn::common::network {
// Platform-specific TUN interface aliases
#if defined(__APPLE__)
using TunInterface = GenericTunInterface<DarwinTunDevice>;
#elif defined(__linux__)
using TunInterface = GenericTunInterface<LinuxTunDevice>;
#elif defined(_WIN32)
using TunInterface = GenericTunInterface<WinTunDevice>;
#endif

using TunInterfacePtr = std::unique_ptr<TunInterface>;
}  // namespace fptn::common::network
