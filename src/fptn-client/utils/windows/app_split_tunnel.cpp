/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "utils/windows/app_split_tunnel.h"

#if _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winioctl.h>
#include <winsvc.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <rpcdce.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {

constexpr wchar_t kDriverDeviceName[] = L"\\\\.\\MULLVADSPLITTUNNEL";
constexpr wchar_t kServiceName[] = L"FptnAppSplitTunnel";
constexpr wchar_t kDriverFileName[] = L"mullvad-split-tunnel.sys";

// Use the same WFP sublayer identities that the production Mullvad Windows
// client passes to win-split-tunnel. The driver was designed to place its
// redirect/permit/fail-closed filters in this policy layout.
//
// If Mullvad/winfw has already created these sublayers, FPTN reuses them and
// never deletes them. If they are absent, FPTN creates compatible bootstrap
// sublayers with the documented priority relationship: baseline is highest,
// DNS is slightly lower.
const GUID kBaselineSublayer = {
    0x21e068a2, 0x2851, 0x43c5, {0x8a, 0x29, 0x7a, 0xfe, 0x3f, 0x26, 0x03, 0x84}};
const GUID kDnsSublayer = {
    0xe65841b6, 0x82f6, 0x4d55, {0xbd, 0xe2, 0x61, 0xf8, 0x4d, 0x45, 0x08, 0xd4}};

constexpr DWORD kStDeviceType = 0x8000u;
constexpr DWORD IOCTL_ST_INITIALIZE = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 1u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_DEQUEUE_EVENT = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 2u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_REGISTER_PROCESSES = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 3u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_REGISTER_IP_ADDRESSES = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 4u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_GET_IP_ADDRESSES = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 5u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_SET_CONFIGURATION = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 6u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_CLEAR_CONFIGURATION = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 8u, METHOD_NEITHER, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_GET_STATE = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 9u, METHOD_BUFFERED, FILE_ANY_ACCESS));
constexpr DWORD IOCTL_ST_RESET = static_cast<DWORD>(
    CTL_CODE(kStDeviceType, 11u, METHOD_NEITHER, FILE_ANY_ACCESS));

constexpr UINT16 kBaselineSublayerWeight = 0xFFFFu;
constexpr UINT16 kDnsSublayerWeight = 0xFFFEu;

struct StSublayerGuids {
  GUID Baseline;
  GUID Dns;
};

struct StConfigurationEntry {
  SIZE_T ImageNameOffset;
  USHORT ImageNameLength;
};

struct StConfigurationHeader {
  SIZE_T NumEntries;
  SIZE_T TotalLength;
};

struct StProcessDiscoveryEntry {
  HANDLE ProcessId;
  HANDLE ParentProcessId;
  SIZE_T ImageNameOffset;
  USHORT ImageNameLength;
};

struct StProcessDiscoveryHeader {
  SIZE_T NumEntries;
  SIZE_T TotalLength;
};

// Layout from the public win-split-tunnel driver ABI.
struct StIpAddresses {
  IN_ADDR TunnelIpv4;
  IN_ADDR InternetIpv4;
  IN6_ADDR TunnelIpv6;
  IN6_ADDR InternetIpv6;
};

enum class StEventId : std::uint32_t {
  kStartSplittingProcess = 0,
  kStopSplittingProcess = 1,
  kErrorStartSplittingProcess = 0x80000001u,
  kErrorStopSplittingProcess = 0x80000002u,
  kErrorMessage = 0x80000003u,
};

struct StEventHeader {
  StEventId EventId;
  SIZE_T EventSize;
  UCHAR EventData[ANYSIZE_ARRAY];
};

struct StSplittingEvent {
  HANDLE ProcessId;
  std::uint32_t Reason;
  USHORT ImageNameLength;
  WCHAR ImageName[ANYSIZE_ARRAY];
};

struct StSplittingErrorEvent {
  HANDLE ProcessId;
  USHORT ImageNameLength;
  WCHAR ImageName[ANYSIZE_ARRAY];
};

struct StErrorMessageEvent {
  LONG Status;
  USHORT ErrorMessageLength;
  WCHAR ErrorMessage[ANYSIZE_ARRAY];
};

struct PhysicalRouteInfo {
  DWORD interface_index = 0;
  IN_ADDR source{};
  IN_ADDR gateway{};
};

struct DirectRouteLease {
  bool owned = false;
  std::chrono::steady_clock::time_point last_seen{};
};

std::string WinErrorMessage(DWORD error) {
  LPSTR buffer = nullptr;
  const DWORD length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
          FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
  std::string result;
  if (length != 0 && buffer != nullptr) {
    result.assign(buffer, length);
    LocalFree(buffer);
    while (!result.empty() &&
           (result.back() == '\r' || result.back() == '\n' ||
               result.back() == ' ')) {
      result.pop_back();
    }
  } else {
    result = "Windows error " + std::to_string(error);
  }
  return result;
}

std::string Ipv4ToString(const IN_ADDR& address) {
  char buffer[INET_ADDRSTRLEN] = {};
  if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&address), buffer,
          static_cast<DWORD>(sizeof(buffer))) == nullptr) {
    return "<invalid>";
  }
  return buffer;
}

std::filesystem::path ExecutableDirectory() {
  std::vector<wchar_t> buffer(32768, L'\0');
  const DWORD count = GetModuleFileNameW(
      nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (count == 0 || count >= buffer.size()) {
    return {};
  }
  return std::filesystem::path(std::wstring(buffer.data(), count)).parent_path();
}

std::wstring NormalizeAbsolutePath(const std::wstring& raw) {
  if (raw.empty()) {
    return {};
  }
  std::vector<wchar_t> buffer(32768, L'\0');
  const DWORD count = GetFullPathNameW(
      raw.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  if (count == 0 || count >= buffer.size()) {
    return raw;
  }
  std::wstring result(buffer.data(), count);
  std::replace(result.begin(), result.end(), L'/', L'\\');
  return result;
}

std::wstring DosPathToDevicePath(const std::wstring& raw_path) {
  const std::wstring path = NormalizeAbsolutePath(raw_path);
  if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') {
    return {};
  }

  wchar_t drive[3] = {static_cast<wchar_t>(std::towupper(path[0])), L':', L'\0'};
  std::vector<wchar_t> device(32768, L'\0');
  const DWORD count =
      QueryDosDeviceW(drive, device.data(), static_cast<DWORD>(device.size()));
  if (count == 0) {
    return {};
  }
  return std::wstring(device.data()) + path.substr(2);
}

std::wstring QueryProcessPath(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) {
    return {};
  }
  std::vector<wchar_t> path(32768, L'\0');
  DWORD size = static_cast<DWORD>(path.size());
  const BOOL ok = QueryFullProcessImageNameW(process, 0, path.data(), &size);
  CloseHandle(process);
  if (!ok || size == 0) {
    return {};
  }
  return std::wstring(path.data(), size);
}

struct ProcessInfo {
  DWORD pid = 0;
  DWORD parent_pid = 0;
  std::wstring device_path;
};

std::vector<ProcessInfo> SnapshotProcesses() {
  std::vector<ProcessInfo> result;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return result;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      ProcessInfo info;
      info.pid = entry.th32ProcessID;
      info.parent_pid = entry.th32ParentProcessID;
      const auto dos_path = QueryProcessPath(info.pid);
      if (!dos_path.empty()) {
        info.device_path = DosPathToDevicePath(dos_path);
      }
      result.push_back(std::move(info));
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return result;
}

std::vector<std::uint8_t> BuildProcessPayload(
    const std::vector<ProcessInfo>& processes) {
  std::size_t string_bytes = 0;
  for (const auto& process : processes) {
    string_bytes += process.device_path.size() * sizeof(wchar_t);
  }

  const std::size_t total_size = sizeof(StProcessDiscoveryHeader) +
                                 sizeof(StProcessDiscoveryEntry) *
                                     processes.size() +
                                 string_bytes;
  std::vector<std::uint8_t> buffer(total_size, 0);
  auto* header = reinterpret_cast<StProcessDiscoveryHeader*>(buffer.data());
  auto* entries = reinterpret_cast<StProcessDiscoveryEntry*>(header + 1);
  auto* string_buffer = reinterpret_cast<std::uint8_t*>(
      entries + processes.size());
  SIZE_T offset = 0;

  for (std::size_t index = 0; index < processes.size(); ++index) {
    const auto& process = processes[index];
    auto& out = entries[index];
    out.ProcessId = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(process.pid));
    out.ParentProcessId = reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(process.parent_pid));
    if (!process.device_path.empty()) {
      const std::size_t bytes = process.device_path.size() * sizeof(wchar_t);
      if (bytes <= std::numeric_limits<USHORT>::max()) {
        out.ImageNameOffset = offset;
        out.ImageNameLength = static_cast<USHORT>(bytes);
        std::memcpy(string_buffer + offset, process.device_path.data(), bytes);
        offset += bytes;
      }
    }
  }

  header->NumEntries = processes.size();
  header->TotalLength = total_size;
  return buffer;
}

std::vector<std::uint8_t> BuildConfigurationPayload(
    const std::vector<std::wstring>& device_paths) {
  std::size_t string_bytes = 0;
  for (const auto& path : device_paths) {
    string_bytes += path.size() * sizeof(wchar_t);
  }

  const std::size_t total_size = sizeof(StConfigurationHeader) +
                                 sizeof(StConfigurationEntry) *
                                     device_paths.size() +
                                 string_bytes;
  std::vector<std::uint8_t> buffer(total_size, 0);
  auto* header = reinterpret_cast<StConfigurationHeader*>(buffer.data());
  auto* entries = reinterpret_cast<StConfigurationEntry*>(header + 1);
  auto* string_buffer =
      reinterpret_cast<std::uint8_t*>(entries + device_paths.size());
  SIZE_T offset = 0;

  for (std::size_t index = 0; index < device_paths.size(); ++index) {
    const auto& path = device_paths[index];
    const std::size_t bytes = path.size() * sizeof(wchar_t);
    if (bytes > std::numeric_limits<USHORT>::max()) {
      continue;
    }
    entries[index].ImageNameOffset = offset;
    entries[index].ImageNameLength = static_cast<USHORT>(bytes);
    std::memcpy(string_buffer + offset, path.data(), bytes);
    offset += bytes;
  }

  header->NumEntries = device_paths.size();
  header->TotalLength = total_size;
  return buffer;
}

bool ParseIpv4(const fptn::common::network::IPv4Address& value, IN_ADDR* out) {
  if (out == nullptr || !value.IsValid()) {
    return false;
  }
  return InetPtonA(AF_INET, value.ToString().c_str(), out) == 1;
}

bool ParseIpv6(const fptn::common::network::IPv6Address& value, IN6_ADDR* out) {
  if (out == nullptr || !value.IsValid()) {
    return false;
  }
  return InetPtonA(AF_INET6, value.ToString().c_str(), out) == 1;
}

bool DetermineInternetRoute(
    const fptn::common::network::IPv4Address& vpn_server,
    PhysicalRouteInfo* out) {
  if (out == nullptr || !vpn_server.IsValid()) {
    return false;
  }

  SOCKADDR_INET destination{};
  destination.si_family = AF_INET;
  if (InetPtonA(AF_INET, vpn_server.ToString().c_str(),
          &destination.Ipv4.sin_addr) != 1) {
    return false;
  }

  MIB_IPFORWARD_ROW2 route{};
  SOCKADDR_INET best_source{};
  const DWORD status =
      GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &best_source);
  if (status != NO_ERROR || best_source.si_family != AF_INET ||
      route.InterfaceIndex == 0) {
    SPDLOG_WARN("App split tunnel: GetBestRoute2 failed: {}", status);
    return false;
  }

  out->interface_index = route.InterfaceIndex;
  out->source = best_source.Ipv4.sin_addr;
  if (route.NextHop.si_family == AF_INET) {
    out->gateway = route.NextHop.Ipv4.sin_addr;
  }

  return out->source.S_un.S_addr != 0;
}

}  // namespace

namespace fptn::utils::windows {

class AppSplitTunnel::Impl final {
 public:
  explicit Impl(Config config) : config_(std::move(config)) {}
  ~Impl() { Stop(); }

  bool Start() {
    if (started_) {
      return true;
    }
    if (config_.excluded_app_paths.empty()) {
      return false;
    }

    const auto exe_dir = ExecutableDirectory();
    driver_path_ = exe_dir / kDriverFileName;
    if (exe_dir.empty() || !std::filesystem::exists(driver_path_)) {
      SPDLOG_WARN(
          "Application split tunnel is enabled, but {} is missing next to "
          "the FPTN executable",
          std::filesystem::path(kDriverFileName).string());
      return false;
    }

    // Clean up a stale service left by a previous FPTN crash before checking
    // whether another VPN client already owns the Mullvad driver device.
    CleanupOwnedService();
    if (DriverDeviceAlreadyExists()) {
      SPDLOG_WARN(
          "Application split tunnel disabled: another process already owns "
          "the Mullvad split-tunnel driver");
      return false;
    }

    if (!StartDriverService()) {
      Cleanup();
      return false;
    }
    if (!OpenDriver()) {
      Cleanup();
      return false;
    }
    if (!OpenWfpSession()) {
      Cleanup();
      return false;
    }
    if (!InitializeDriver()) {
      Cleanup();
      return false;
    }
    driver_initialized_ = true;
    LogDriverState("after initialize");
    if (!RegisterProcessTree()) {
      Cleanup();
      return false;
    }
    LogDriverState("after process registration");
    if (!StartEventThread()) {
      Cleanup();
      return false;
    }
    if (!SetExcludedApplications()) {
      Cleanup();
      return false;
    }
    LogDriverState("after configuration");
    if (!RegisterAddresses()) {
      Cleanup();
      return false;
    }

    LogDriverState("after IP registration");
    LogRegisteredAddresses();
    if (!StartRouteHelper()) {
      Cleanup();
      return false;
    }

    started_ = true;
    SPDLOG_INFO("Application split tunnel engaged for {} executable(s)",
        config_.excluded_app_paths.size());
    return true;
  }

  void Stop() {
    Cleanup();
    started_ = false;
  }

  bool IsStarted() const { return started_; }

 private:
  bool DriverDeviceAlreadyExists() const {
    HANDLE handle = CreateFileW(kDriverDeviceName,
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      return false;
    }
    CloseHandle(handle);
    return true;
  }

  void CleanupOwnedService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
      return;
    }
    SC_HANDLE service = OpenServiceW(scm, kServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service != nullptr) {
      SERVICE_STATUS status{};
      ControlService(service, SERVICE_CONTROL_STOP, &status);
      for (int i = 0; i < 20; ++i) {
        SERVICE_STATUS_PROCESS current{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&current), sizeof(current), &needed) ||
            current.dwCurrentState == SERVICE_STOPPED) {
          break;
        }
        Sleep(100);
      }
      DeleteService(service);
      CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
  }

  bool StartDriverService() {
    scm_ = OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scm_ == nullptr) {
      SPDLOG_WARN("App split tunnel: OpenSCManager failed: {}",
          WinErrorMessage(GetLastError()));
      return false;
    }

    const std::wstring path = driver_path_.wstring();
    service_ = CreateServiceW(scm_, kServiceName, kServiceName,
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (service_ == nullptr) {
      const DWORD error = GetLastError();
      if (error == ERROR_SERVICE_EXISTS || error == ERROR_DUP_NAME) {
        service_ = OpenServiceW(scm_, kServiceName,
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
      }
    }
    if (service_ == nullptr) {
      SPDLOG_WARN("App split tunnel: unable to create/open driver service: {}",
          WinErrorMessage(GetLastError()));
      return false;
    }

    if (!StartServiceW(service_, 0, nullptr)) {
      const DWORD error = GetLastError();
      if (error != ERROR_SERVICE_ALREADY_RUNNING) {
        SPDLOG_WARN("App split tunnel: driver failed to start: {}",
            WinErrorMessage(error));
        return false;
      }
    }

    for (int i = 0; i < 50; ++i) {
      SERVICE_STATUS_PROCESS status{};
      DWORD needed = 0;
      if (QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
              reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
          return true;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
          SPDLOG_WARN("App split tunnel: driver service stopped with code {}",
              status.dwWin32ExitCode);
          return false;
        }
      }
      Sleep(100);
    }
    SPDLOG_WARN("App split tunnel: timeout while starting driver service");
    return false;
  }

  bool OpenDriver() {
    for (int i = 0; i < 30; ++i) {
      device_ = CreateFileW(kDriverDeviceName, GENERIC_READ | GENERIC_WRITE, 0,
          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (device_ != INVALID_HANDLE_VALUE) {
        return true;
      }
      Sleep(100);
    }
    SPDLOG_WARN("App split tunnel: unable to open driver device: {}",
        WinErrorMessage(GetLastError()));
    return false;
  }

  bool EnsureSublayer(const GUID& key, const wchar_t* name, UINT16 weight,
      bool* created_by_us) {
    if (created_by_us == nullptr) {
      return false;
    }
    *created_by_us = false;

    FWPM_SUBLAYER0* existing = nullptr;
    const DWORD get_status = FwpmSubLayerGetByKey0(wfp_engine_, &key, &existing);
    if (get_status == ERROR_SUCCESS) {
      if (existing != nullptr) {
        SPDLOG_INFO("App split tunnel: reusing existing WFP sublayer '{}' weight={}",
            std::filesystem::path(name).string(), existing->weight);
        FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
      }
      return true;
    }
    if (get_status != FWP_E_SUBLAYER_NOT_FOUND) {
      SPDLOG_WARN("App split tunnel: FwpmSubLayerGetByKey0 failed: 0x{:x}",
          get_status);
      return false;
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = key;
    sublayer.displayData.name = const_cast<wchar_t*>(name);
    sublayer.displayData.description =
        const_cast<wchar_t*>(L"FPTN application split tunnel compatibility layer");
    sublayer.flags = 0;
    sublayer.weight = weight;
    const DWORD add_status = FwpmSubLayerAdd0(wfp_engine_, &sublayer, nullptr);
    if (add_status != ERROR_SUCCESS) {
      SPDLOG_WARN("App split tunnel: FwpmSubLayerAdd0 failed: 0x{:x}",
          add_status);
      return false;
    }

    *created_by_us = true;
    SPDLOG_INFO("App split tunnel: created WFP sublayer '{}' weight={}",
        std::filesystem::path(name).string(), weight);
    return true;
  }

  bool OpenWfpSession() {
    // The kernel driver opens its own WFP session and references the supplied
    // sublayers from that session, so the bootstrap sublayers must not be
    // objects owned by a dynamic user-mode session.
    FWPM_SESSION0 session{};
    session.flags = 0;
    session.displayData.name =
        const_cast<wchar_t*>(L"FPTN application split tunnel bootstrap");
    const DWORD status =
        FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session,
            &wfp_engine_);
    if (status != ERROR_SUCCESS) {
      SPDLOG_WARN("App split tunnel: FwpmEngineOpen0 failed: 0x{:x}", status);
      return false;
    }

    return EnsureSublayer(kBaselineSublayer,
               L"Mullvad VPN baseline-compatible sublayer",
               kBaselineSublayerWeight, &owns_baseline_sublayer_) &&
           EnsureSublayer(kDnsSublayer,
               L"Mullvad VPN DNS-compatible sublayer",
               kDnsSublayerWeight, &owns_dns_sublayer_);
  }

  bool SendIoctl(DWORD code, void* input, DWORD input_size) const {
    DWORD bytes = 0;
    if (!DeviceIoControl(device_, code, input, input_size, nullptr, 0, &bytes,
            nullptr)) {
      SPDLOG_WARN("App split tunnel: DeviceIoControl 0x{:x} failed: {}", code,
          WinErrorMessage(GetLastError()));
      return false;
    }
    return true;
  }

  bool ReceiveIoctl(
      DWORD code, void* output, DWORD output_size, DWORD* bytes_out) const {
    DWORD bytes = 0;
    if (!DeviceIoControl(device_, code, nullptr, 0, output, output_size, &bytes,
            nullptr)) {
      SPDLOG_WARN("App split tunnel: DeviceIoControl(read) 0x{:x} failed: {}",
          code, WinErrorMessage(GetLastError()));
      return false;
    }
    if (bytes_out != nullptr) {
      *bytes_out = bytes;
    }
    return true;
  }

  void LogDriverState(const char* stage) const {
    DWORD state = 0;
    DWORD bytes = 0;
    if (ReceiveIoctl(IOCTL_ST_GET_STATE, &state, sizeof(state), &bytes) &&
        bytes >= sizeof(state)) {
      SPDLOG_INFO("App split tunnel: driver state {} = {}", stage, state);
    }
  }

  void LogRegisteredAddresses() const {
    StIpAddresses addresses{};
    DWORD bytes = 0;
    if (!ReceiveIoctl(IOCTL_ST_GET_IP_ADDRESSES, &addresses,
            sizeof(addresses), &bytes) ||
        bytes < sizeof(addresses)) {
      return;
    }
    SPDLOG_INFO(
        "App split tunnel: driver IPs tunnel-v4={} internet-v4={}",
        Ipv4ToString(addresses.TunnelIpv4),
        Ipv4ToString(addresses.InternetIpv4));
  }

  bool InitializeDriver() {
    StSublayerGuids guids{};
    guids.Baseline = kBaselineSublayer;
    guids.Dns = kDnsSublayer;
    return SendIoctl(IOCTL_ST_INITIALIZE, &guids, sizeof(guids));
  }

  bool RegisterProcessTree() {
    const auto processes = SnapshotProcesses();
    if (processes.empty()) {
      SPDLOG_WARN("App split tunnel: process snapshot is empty");
      return false;
    }
    auto payload = BuildProcessPayload(processes);
    return SendIoctl(IOCTL_ST_REGISTER_PROCESSES, payload.data(),
        static_cast<DWORD>(payload.size()));
  }

  bool SetExcludedApplications() {
    std::vector<std::wstring> device_paths;
    device_paths.reserve(config_.excluded_app_paths.size());
    for (const auto& app : config_.excluded_app_paths) {
      const auto device_path = DosPathToDevicePath(app);
      if (device_path.empty()) {
        SPDLOG_WARN("App split tunnel: cannot convert selected executable "
                    "path to NT device path");
        continue;
      }
      device_paths.push_back(device_path);
    }
    if (device_paths.empty()) {
      SPDLOG_WARN("App split tunnel: no valid application paths");
      return false;
    }
    auto payload = BuildConfigurationPayload(device_paths);
    return SendIoctl(IOCTL_ST_SET_CONFIGURATION, payload.data(),
        static_cast<DWORD>(payload.size()));
  }

  bool RegisterAddresses() {
    StIpAddresses addresses{};
    if (!ParseIpv4(config_.tunnel_ipv4, &addresses.TunnelIpv4)) {
      SPDLOG_WARN("App split tunnel: invalid tunnel IPv4 address");
      return false;
    }
    ParseIpv6(config_.tunnel_ipv6, &addresses.TunnelIpv6);
    if (!DetermineInternetRoute(config_.vpn_server_ip, &physical_route_)) {
      SPDLOG_WARN("App split tunnel: unable to determine primary IPv4 "
                  "interface route");
      return false;
    }
    addresses.InternetIpv4 = physical_route_.source;

    // Internet IPv6 deliberately stays zero for now. This keeps IPv6
    // fail-closed until the physical IPv6 path is tracked as well.
    SPDLOG_INFO(
        "App split tunnel: registering IPs tunnel-v4={} internet-v4={} "
        "physical-if={} gateway={}",
        Ipv4ToString(addresses.TunnelIpv4),
        Ipv4ToString(addresses.InternetIpv4), physical_route_.interface_index,
        Ipv4ToString(physical_route_.gateway));
    return SendIoctl(
        IOCTL_ST_REGISTER_IP_ADDRESSES, &addresses, sizeof(addresses));
  }

  bool StartEventThread() {
    event_stop_ = false;
    try {
      event_thread_ = std::thread([this]() { DriverEventLoop(); });
    } catch (const std::exception& e) {
      SPDLOG_WARN("App split tunnel: unable to start driver event thread: {}",
          e.what());
      return false;
    }
    return true;
  }

  void StopEventThread() {
    event_stop_ = true;
    if (!event_thread_.joinable()) {
      return;
    }
    // IOCTL_ST_DEQUEUE_EVENT is intentionally a blocking request. Cancel the
    // synchronous request issued by the event thread so it can exit cleanly.
    CancelSynchronousIo(event_thread_.native_handle());
    event_thread_.join();
    const std::scoped_lock lock(split_pid_mutex_);
    split_pids_.clear();
  }

  void HandleDriverEvent(const std::uint8_t* buffer, DWORD size) {
    if (buffer == nullptr || size < offsetof(StEventHeader, EventData)) {
      return;
    }
    const auto* header = reinterpret_cast<const StEventHeader*>(buffer);
    const std::size_t header_size = offsetof(StEventHeader, EventData);
    if (header->EventSize > static_cast<SIZE_T>(size - header_size)) {
      SPDLOG_WARN("App split tunnel: malformed driver event");
      return;
    }

    switch (header->EventId) {
      case StEventId::kStartSplittingProcess:
      case StEventId::kStopSplittingProcess: {
        if (header->EventSize < offsetof(StSplittingEvent, ImageName)) {
          return;
        }
        const auto* event = reinterpret_cast<const StSplittingEvent*>(
            header->EventData);
        const DWORD pid = static_cast<DWORD>(
            reinterpret_cast<ULONG_PTR>(event->ProcessId));
        if (pid == 0) {
          return;
        }
        const std::scoped_lock lock(split_pid_mutex_);
        if (header->EventId == StEventId::kStartSplittingProcess) {
          split_pids_.insert(pid);
          SPDLOG_INFO("App split tunnel: process {} entered exclusion", pid);
        } else {
          split_pids_.erase(pid);
          SPDLOG_INFO("App split tunnel: process {} left exclusion", pid);
        }
        break;
      }
      case StEventId::kErrorStartSplittingProcess:
      case StEventId::kErrorStopSplittingProcess: {
        if (header->EventSize < offsetof(StSplittingErrorEvent, ImageName)) {
          return;
        }
        const auto* event = reinterpret_cast<const StSplittingErrorEvent*>(
            header->EventData);
        const DWORD pid = static_cast<DWORD>(
            reinterpret_cast<ULONG_PTR>(event->ProcessId));
        SPDLOG_WARN("App split tunnel: driver reported process split error "
                    "for PID {}", pid);
        break;
      }
      case StEventId::kErrorMessage: {
        if (header->EventSize < offsetof(StErrorMessageEvent, ErrorMessage)) {
          return;
        }
        const auto* event = reinterpret_cast<const StErrorMessageEvent*>(
            header->EventData);
        SPDLOG_WARN("App split tunnel: driver error event status=0x{:08x}",
            static_cast<std::uint32_t>(event->Status));
        break;
      }
      default:
        break;
    }
  }

  void DriverEventLoop() {
    std::vector<std::uint8_t> buffer(4096, 0);
    while (!event_stop_) {
      DWORD bytes = 0;
      const BOOL ok = DeviceIoControl(device_, IOCTL_ST_DEQUEUE_EVENT, nullptr,
          0, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr);
      if (!ok) {
        const DWORD error = GetLastError();
        if (event_stop_ || error == ERROR_OPERATION_ABORTED ||
            error == ERROR_INVALID_HANDLE) {
          break;
        }
        SPDLOG_WARN("App split tunnel: dequeue event failed: {}",
            WinErrorMessage(error));
        Sleep(250);
        continue;
      }
      HandleDriverEvent(buffer.data(), bytes);
    }
  }

  bool StartRouteHelper() {
    if (physical_route_.interface_index == 0 ||
        physical_route_.source.S_un.S_addr == 0) {
      SPDLOG_WARN("App split tunnel: route helper has no physical interface");
      return false;
    }
    route_stop_ = false;
    try {
      route_thread_ = std::thread([this]() { RouteHelperLoop(); });
    } catch (const std::exception& e) {
      SPDLOG_WARN("App split tunnel: unable to start route helper: {}",
          e.what());
      return false;
    }
    SPDLOG_INFO(
        "App split tunnel: TCP direct-route helper active on interface {} "
        "via {}", physical_route_.interface_index,
        Ipv4ToString(physical_route_.gateway));
    return true;
  }

  void StopRouteHelper() {
    route_stop_ = true;
    if (route_thread_.joinable()) {
      route_thread_.join();
    }
    for (const auto& [address, lease] : direct_routes_) {
      if (lease.owned) {
        DeleteDirectHostRoute(address);
      }
    }
    direct_routes_.clear();
  }

  std::unordered_set<ULONG> GetSplitTcpRemoteAddresses() const {
    std::unordered_set<DWORD> pids;
    {
      const std::scoped_lock lock(split_pid_mutex_);
      pids = split_pids_;
    }
    if (pids.empty()) {
      return {};
    }

    DWORD size = 0;
    DWORD status = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) {
      return {};
    }
    if (size == 0) {
      return {};
    }

    std::vector<std::uint8_t> storage(size, 0);
    status = GetExtendedTcpTable(storage.data(), &size, FALSE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_SUCCESS) {
      return {};
    }

    const auto* table =
        reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(storage.data());
    std::unordered_set<ULONG> remotes;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
      const auto& row = table->table[i];
      if (pids.find(row.dwOwningPid) == pids.end()) {
        continue;
      }
      if (row.dwState == MIB_TCP_STATE_CLOSED ||
          row.dwState == MIB_TCP_STATE_LISTEN ||
          row.dwState == MIB_TCP_STATE_DELETE_TCB || row.dwRemoteAddr == 0) {
        continue;
      }
      const ULONG host_order = ntohl(row.dwRemoteAddr);
      const ULONG first_octet = (host_order >> 24u) & 0xffu;
      if (first_octet == 0u || first_octet == 127u || first_octet >= 224u) {
        continue;
      }
      remotes.insert(row.dwRemoteAddr);
    }
    return remotes;
  }

  MIB_IPFORWARD_ROW2 MakeDirectHostRoute(ULONG remote_address) const {
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = physical_route_.interface_index;

    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = remote_address;
    row.DestinationPrefix.PrefixLength = 32;

    row.NextHop.si_family = AF_INET;
    row.NextHop.Ipv4.sin_family = AF_INET;
    row.NextHop.Ipv4.sin_addr = physical_route_.gateway;

    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Origin = NlroManual;
    return row;
  }

  bool EnsureDirectHostRoute(ULONG remote_address, bool* owned) const {
    if (owned == nullptr) {
      return false;
    }
    *owned = false;
    auto route = MakeDirectHostRoute(remote_address);
    DWORD status = CreateIpForwardEntry2(&route);
    if (status == ERROR_SUCCESS) {
      *owned = true;
      IN_ADDR address{};
      address.S_un.S_addr = remote_address;
      SPDLOG_INFO("App split tunnel: direct TCP host route {} /32 -> if {}",
          Ipv4ToString(address), physical_route_.interface_index);
      return true;
    }
    if (status == ERROR_OBJECT_ALREADY_EXISTS) {
      // Respect routes that predated FPTN; never delete them on cleanup.
      return true;
    }
    IN_ADDR address{};
    address.S_un.S_addr = remote_address;
    SPDLOG_WARN("App split tunnel: failed to add direct route for {}: {}",
        Ipv4ToString(address), WinErrorMessage(status));
    return false;
  }

  void DeleteDirectHostRoute(ULONG remote_address) const {
    auto route = MakeDirectHostRoute(remote_address);
    const DWORD status = DeleteIpForwardEntry2(&route);
    if (status != ERROR_SUCCESS && status != ERROR_NOT_FOUND) {
      IN_ADDR address{};
      address.S_un.S_addr = remote_address;
      SPDLOG_WARN("App split tunnel: failed to delete direct route for {}: {}",
          Ipv4ToString(address), WinErrorMessage(status));
    }
  }

  void RouteHelperLoop() {
    constexpr auto kPollInterval = std::chrono::milliseconds(50);
    constexpr auto kRouteGrace = std::chrono::seconds(5);
    constexpr std::size_t kMaxDirectRoutes = 2048;

    while (!route_stop_) {
      const auto remotes = GetSplitTcpRemoteAddresses();
      const auto now = std::chrono::steady_clock::now();

      for (const ULONG address : remotes) {
        auto it = direct_routes_.find(address);
        if (it != direct_routes_.end()) {
          it->second.last_seen = now;
          continue;
        }
        if (direct_routes_.size() >= kMaxDirectRoutes) {
          SPDLOG_WARN("App split tunnel: direct-route limit reached");
          break;
        }
        bool owned = false;
        if (EnsureDirectHostRoute(address, &owned)) {
          direct_routes_.emplace(address, DirectRouteLease{owned, now});
        }
      }

      for (auto it = direct_routes_.begin(); it != direct_routes_.end();) {
        if (remotes.find(it->first) != remotes.end() ||
            now - it->second.last_seen <= kRouteGrace) {
          ++it;
          continue;
        }
        if (it->second.owned) {
          DeleteDirectHostRoute(it->first);
        }
        it = direct_routes_.erase(it);
      }

      std::this_thread::sleep_for(kPollInterval);
    }
  }

  void Cleanup() {
    StopRouteHelper();
    StopEventThread();

    if (device_ != INVALID_HANDLE_VALUE && driver_initialized_) {
      DWORD bytes = 0;
      DeviceIoControl(device_, IOCTL_ST_CLEAR_CONFIGURATION, nullptr, 0,
          nullptr, 0, &bytes, nullptr);
      DeviceIoControl(device_, IOCTL_ST_RESET, nullptr, 0, nullptr, 0, &bytes,
          nullptr);
      driver_initialized_ = false;
    }
    if (device_ != INVALID_HANDLE_VALUE) {
      CloseHandle(device_);
      device_ = INVALID_HANDLE_VALUE;
    }

    // Keep the bootstrap WFP engine open until the driver is fully stopped.
    // Unlike the previous implementation this is intentionally NOT a dynamic
    // session, because the kernel driver must be able to reference these
    // sublayers from its own WFP session.

    if (service_ != nullptr) {
      SERVICE_STATUS status{};
      ControlService(service_, SERVICE_CONTROL_STOP, &status);
      for (int i = 0; i < 30; ++i) {
        SERVICE_STATUS_PROCESS current{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&current), sizeof(current), &needed) ||
            current.dwCurrentState == SERVICE_STOPPED) {
          break;
        }
        Sleep(100);
      }
      DeleteService(service_);
      CloseServiceHandle(service_);
      service_ = nullptr;
    }
    if (scm_ != nullptr) {
      CloseServiceHandle(scm_);
      scm_ = nullptr;
    }

    // The driver is now unloaded, so no callouts/filters can still reference
    // our bootstrap sublayers. Remove them explicitly before closing the
    // non-dynamic WFP session.
    if (wfp_engine_ != nullptr) {
      if (owns_dns_sublayer_) {
        const DWORD dns_status =
            FwpmSubLayerDeleteByKey0(wfp_engine_, &kDnsSublayer);
        if (dns_status != ERROR_SUCCESS &&
            dns_status != FWP_E_SUBLAYER_NOT_FOUND) {
          SPDLOG_WARN(
              "App split tunnel: unable to remove owned DNS sublayer: 0x{:x}",
              dns_status);
        }
      }

      if (owns_baseline_sublayer_) {
        const DWORD baseline_status =
            FwpmSubLayerDeleteByKey0(wfp_engine_, &kBaselineSublayer);
        if (baseline_status != ERROR_SUCCESS &&
            baseline_status != FWP_E_SUBLAYER_NOT_FOUND) {
          SPDLOG_WARN(
              "App split tunnel: unable to remove owned baseline sublayer: 0x{:x}",
              baseline_status);
        }
      }

      owns_dns_sublayer_ = false;
      owns_baseline_sublayer_ = false;
      FwpmEngineClose0(wfp_engine_);
      wfp_engine_ = nullptr;
    }
  }

  Config config_;
  bool started_ = false;
  bool driver_initialized_ = false;
  std::filesystem::path driver_path_;
  SC_HANDLE scm_ = nullptr;
  SC_HANDLE service_ = nullptr;
  HANDLE device_ = INVALID_HANDLE_VALUE;
  HANDLE wfp_engine_ = nullptr;
  bool owns_baseline_sublayer_ = false;
  bool owns_dns_sublayer_ = false;

  PhysicalRouteInfo physical_route_{};
  std::atomic<bool> event_stop_{false};
  std::thread event_thread_;
  mutable std::mutex split_pid_mutex_;
  std::unordered_set<DWORD> split_pids_;

  std::atomic<bool> route_stop_{false};
  std::thread route_thread_;
  std::unordered_map<ULONG, DirectRouteLease> direct_routes_;
};

AppSplitTunnel::AppSplitTunnel(Config config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

AppSplitTunnel::~AppSplitTunnel() = default;

bool AppSplitTunnel::Start() { return impl_->Start(); }
void AppSplitTunnel::Stop() { impl_->Stop(); }
bool AppSplitTunnel::IsStarted() const { return impl_->IsStarted(); }

}  // namespace fptn::utils::windows

#endif  // _WIN32
