/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov
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
#include "common/network/data_rate_calculator.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

namespace fptn::common::network {

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
 *  - SendBatchImpl()      - Packet transmission
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
    int mtu_size;
    bool using_rate_calculator;

    IPv4Address ipv4_addr;
    std::uint32_t ipv4_netmask = 32;
    IPv6Address ipv6_addr;
    std::uint32_t ipv6_netmask = 126;
  };

  bool Start() { return impl()->StartImpl(); }

  bool Stop() { return impl()->StopImpl(); }

  bool Send(IPPacketPtr packet) { return impl()->SendImpl(std::move(packet)); }

  bool SendBatch(BatchIPPacketPtr packets) {
    return impl()->SendBatchImpl(std::move(packets));
  }

  std::size_t GetSendRate() { return impl()->GetSendRateImpl(); }

  std::size_t GetReceiveRate() { return impl()->GetReceiveRateImpl(); }

  void SetName(const std::string& name) { name_ = name; }

 private:
  explicit BaseNetInterface(Config config)
      : config_(std::move(config)),
        name_(config_.name),
        recv_ip_packet_callback_(nullptr) {}

  Implementation* impl() { return static_cast<Implementation*>(this); }

 public:
  [[nodiscard]] const std::string& Name() const noexcept { return name_; }

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

  [[nodiscard]] int MtuSize() const noexcept { return config_.mtu_size; }

  bool UsingRateCalculator() const noexcept {
    return config_.using_rate_calculator;
  }

  int IPv6Netmask() const noexcept { return config_.ipv6_netmask; }

  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept {
    recv_ip_packet_callback_ = callback;
  }

  [[nodiscard]] NewIPPacketCallback GetRecvIPPacketCallback() const {
    return recv_ip_packet_callback_;
  }

 private:
  const Config config_;
  std::string name_;
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
      : Base(std::move(config)),
        running_(false),
        to_network_("tun_interface") {}

  ~GenericTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

    if (running_) {
      return true;  // Already started — guard against double-start
    }

    try {
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.Open(this->Name())) {
        SPDLOG_ERROR("Failed to open TUN device");
        return false;
      }
      // Update name to actual device name (may differ, e.g., utun on macOS)
      this->SetName(device_.GetName());

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
      device_.SetMTU(this->MtuSize());
      device_.BringUp();

      running_ = true;
      device_.SetStopFlag(&running_);
      thread_reader_ = std::thread(&GenericTunInterface::RunReader, this);
      thread_sender_ = std::thread(&GenericTunInterface::RunSender, this);
      return thread_reader_.joinable() && thread_sender_.joinable();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("Error start: {}", ex.what());
    }
    return false;
  }

  bool StopImpl() noexcept {
    if (!running_) {
      return false;
    }
    {
      const std::scoped_lock lock(mutex_);  // mutex

      // cppcheck-suppress identicalConditionAfterEarlyExit
      if (!running_) {  // Double-check after acquiring lock
        return false;
      }
      running_ = false;
    }

    if (thread_reader_.joinable()) {
      thread_reader_.join();
    }

    if (thread_sender_.joinable()) {
      thread_sender_.join();
    }

    device_.Close();

    return true;
  }

  bool SendImpl(IPPacketPtr packet) noexcept {
    return to_network_.Push(std::move(packet));
  }

  bool SendBatchImpl(BatchIPPacketPtr packets) noexcept {
    return to_network_.PushBatch(std::move(packets));
  }

  std::size_t GetSendRateImpl() const noexcept {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRateImpl() const noexcept {
    return receive_rate_calculator_.GetRateForSecond();
  }

  void RunReader() {
    const int mtu_size = this->MtuSize();
    const auto callback = this->GetRecvIPPacketCallback();
    const bool rate_calc = this->UsingRateCalculator();

    IPPacketData buffer(mtu_size);
    while (running_) {
      const int size = device_.Read(buffer.data(), mtu_size);
      if (size > 0) {
        auto packet = IPPacket::Parse(buffer.data(), size);
        if (packet != nullptr && running_) {
          if (callback) {
            callback(std::move(packet));
          }
          if (rate_calc) {
            receive_rate_calculator_.Update(size);  // calculate rate
          }
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  void RunSender() {
    try {
      constexpr std::chrono::milliseconds kTimeout{100};
      static const bool kRateCalculator = this->UsingRateCalculator();
      while (running_) {
        auto packets = to_network_.WaitForPackets(kTimeout);
        // cppcheck-suppress constVariableReference
        for (auto& packet : packets) {
          if (packet) {
            const auto& data = packet->Data();
            // send data
            if (!data.empty() && running_) {
              const int data_size = static_cast<int>(data.size());
              int bytes_written = 0;
              do {
                // resend if error
                bytes_written = device_.Write(data.data(), data_size);
                if (bytes_written == data_size && kRateCalculator) {
                  send_rate_calculator_.Update(bytes_written);
                }
              } while (bytes_written != data_size && running_);
            }
          }
        }
      }
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("SendImpl error: {}", ex.what());
    }
  }

 private:
  mutable std::mutex mutex_;

  std::atomic<bool> running_;
  std::thread thread_reader_;
  std::thread thread_sender_;

  Device device_;
  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;

  fptn::common::data::Channel to_network_;
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

using TunInterfaceSPtr = std::shared_ptr<TunInterface>;
}  // namespace fptn::common::network
