/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstring>
#include <string>

// clang-format off
#include <Ws2tcpip.h>   // NOLINT(build/include_order)
#include <windows.h>     // NOLINT(build/include_order)
#include <objbase.h>     // NOLINT(build/include_order)
#include <winsock2.h>    // NOLINT(build/include_order)
#include <Iprtrmib.h>    // NOLINT(build/include_order)
#include <iphlpapi.h>    // NOLINT(build/include_order)
#include <WinError.h>    // NOLINT(build/include_order)
#include <wintun.h>      // NOLINT(build/include_order)
// clang-format on

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"

namespace fptn::common::network {

class WinTunDevice {
 public:
  WinTunDevice()
      : wintun_(nullptr),
        adapter_(nullptr),
        session_(nullptr),
        running_(nullptr) {
    wintun_ = InitializeWintun();
    UuidCreate(&guid_);
  }

  ~WinTunDevice() { Close(); }

  WinTunDevice(const WinTunDevice&) = delete;
  WinTunDevice& operator=(const WinTunDevice&) = delete;

  bool Open(const std::string& name) {
    if (!wintun_) {
      return false;
    }
    SPDLOG_INFO("WINTUN: {} version loaded",
        ParseWinTunVersion(WintunGetRunningDriverVersion()));

    name_ = name;
    const std::wstring interface_name = ToWString(name);
    adapter_ = WintunCreateAdapter(
        interface_name.c_str(), interface_name.c_str(), &guid_);
    if (!adapter_) {
      SPDLOG_ERROR("Network adapter wasn't created!");
      return false;
    }
    return true;
  }

  void Close() {
    if (session_) {
      WintunEndSession(session_);
      session_ = nullptr;
    }
    if (adapter_) {
      WintunCloseAdapter(adapter_);
      adapter_ = nullptr;
    }
    if (wintun_) {
      WintunDeleteDriver();
      wintun_ = nullptr;
    }
  }

  [[nodiscard]] const std::string& GetName() const { return name_; }

  bool ConfigureIPv4(const std::string& addr, int mask) {
    return SetIPAddressEntry(AF_INET, addr, mask);
  }

  bool ConfigureIPv6(const std::string& addr, int mask) {
    return SetIPAddressEntry(AF_INET6, addr, mask);
  }

  // cppcheck-suppress functionStatic
  void SetNonBlocking(bool /*enabled*/) {
    // Wintun uses event-based I/O, no-op
  }

  // cppcheck-suppress functionStatic
  void SetMTU(int /*mtu*/) {
    // Wintun handles MTU internally, no-op
  }

  void BringUp() {
    constexpr int kSessionCapacity = 0x20000;
    session_ = WintunStartSession(adapter_, kSessionCapacity);
    if (!session_) {
      SPDLOG_ERROR("Open session error");
    }
  }

  int Read(void* buffer, int size) {
    if (!session_) {
      return 0;
    }

    constexpr std::size_t kRetryAmount = 20;
    while (running_ && *running_) {
      for (std::size_t i = 0; i < kRetryAmount; ++i) {
        DWORD packet_size = 0;
        BYTE* packet = WintunReceivePacket(session_, &packet_size);
        if (packet && running_ && *running_) {
          const int copy_size = (static_cast<int>(packet_size) < size)
                                    ? static_cast<int>(packet_size)
                                    : size;
          std::memcpy(buffer, packet, copy_size);
          WintunReleaseReceivePacket(session_, packet);
          return copy_size;
        }
        if (GetLastError() == ERROR_NO_MORE_ITEMS) {
          continue;
        }
        return 0;
      }
      WaitForSingleObject(WintunGetReadWaitEvent(session_), 10);
    }
    return 0;
  }

  int Write(const void* data, int size) {
    if (!session_ || !data || size <= 0) {
      return 0;
    }

    BYTE* send_buffer =
        WintunAllocateSendPacket(session_, static_cast<DWORD>(size));
    if (!send_buffer) {
      return 0;
    }
    std::memcpy(send_buffer, data, size);
    WintunSendPacket(session_, send_buffer);
    return size;
  }

  void SetStopFlag(const std::atomic<bool>* running) { running_ = running; }

 private:
  bool SetIPAddressEntry(int family, const std::string& addr, int mask) {
    MIB_UNICASTIPADDRESS_ROW address_row;
    InitializeUnicastIpAddressEntry(&address_row);
    WintunGetAdapterLUID(adapter_, &address_row.InterfaceLuid);

    if (family == AF_INET) {
      address_row.Address.Ipv4.sin_family = AF_INET;
      if (1 != inet_pton(AF_INET, addr.c_str(),
                   &(address_row.Address.Ipv4.sin_addr))) {
        SPDLOG_ERROR("Wrong IPv4 address");
        return false;
      }
    } else {
      address_row.Address.Ipv6.sin6_family = AF_INET6;
      if (1 != inet_pton(AF_INET6, addr.c_str(),
                   &(address_row.Address.Ipv6.sin6_addr))) {
        SPDLOG_ERROR("Wrong IPv6 address");
        return false;
      }
    }

    address_row.OnLinkPrefixLength = static_cast<BYTE>(mask);
    address_row.DadState = IpDadStatePreferred;

    const auto res = CreateUnicastIpAddressEntry(&address_row);
    if (res != ERROR_SUCCESS && res != ERROR_OBJECT_ALREADY_EXISTS) {
      SPDLOG_ERROR("Failed to set {} address", addr);
      return false;
    }
    return true;
  }

  static std::wstring ToWString(const std::string& s) {
    return {s.begin(), s.end()};
  }

  static std::string ParseWinTunVersion(DWORD version_number) {
    return std::to_string((version_number >> 16) & 0xff) + "." +
           std::to_string((version_number >> 0) & 0xff);
  }

  HMODULE InitializeWintun() {
    HMODULE wintun_lib = LoadLibraryExW(L"wintun.dll", nullptr,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!wintun_lib) {
      SPDLOG_ERROR("WINTUN NOT FOUND!");
      return nullptr;
    }
#define X(Name)                            \
  ((*(reinterpret_cast<FARPROC*>(&Name)) = \
           GetProcAddress(wintun_lib, #Name)) == nullptr)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) ||
        X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) ||
        X(WintunSetLogger) || X(WintunStartSession) || X(WintunEndSession) ||
        X(WintunGetReadWaitEvent) || X(WintunReceivePacket) ||
        X(WintunReleaseReceivePacket) || X(WintunAllocateSendPacket) ||
        X(WintunSendPacket)) {
      DWORD last_error = GetLastError();
      FreeLibrary(wintun_lib);
      SetLastError(last_error);
      SPDLOG_ERROR("Error whilst loading the lib: {}", last_error);
      return nullptr;
    }
#undef X
    SPDLOG_INFO("Wintun initialization successful");
    return wintun_lib;
  }

  // Wintun function pointers
  WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter = nullptr;
  WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter = nullptr;
  WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter = nullptr;
  WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID = nullptr;
  WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion =
      nullptr;
  WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver = nullptr;
  WINTUN_SET_LOGGER_FUNC* WintunSetLogger = nullptr;
  WINTUN_START_SESSION_FUNC* WintunStartSession = nullptr;
  WINTUN_END_SESSION_FUNC* WintunEndSession = nullptr;
  WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent = nullptr;
  WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket = nullptr;
  WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket = nullptr;
  WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket = nullptr;
  WINTUN_SEND_PACKET_FUNC* WintunSendPacket = nullptr;

  GUID guid_;
  HMODULE wintun_;
  WINTUN_ADAPTER_HANDLE adapter_;
  WINTUN_SESSION_HANDLE session_;

  std::string name_;
  const std::atomic<bool>* running_;
};

}  // namespace fptn::common::network
