#include "fptn-vless/platform.h"

#include <utility>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace fptn::vless::platform {

namespace {

std::wstring Widen(const std::string& text) {
  if (text.empty()) {
    return {};
  }
  const int size = MultiByteToWideChar(
      CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
      out.data(), size);
  return out;
}

std::wstring ExePathW() {
  std::wstring path(MAX_PATH, L'\0');
  for (;;) {
    const DWORD n = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (n == 0) {
      return {};
    }
    if (n < path.size()) {
      path.resize(n);
      return path;
    }
    path.resize(path.size() * 2);
  }
}

HANDLE g_instance_mutex = nullptr;

}  // namespace

bool AcquireSingleInstance() {
  g_instance_mutex = CreateMutexW(nullptr, TRUE, L"Local\\fptn-vless-instance");
  if (g_instance_mutex == nullptr) {
    return true;  // cannot tell: better to run than to refuse
  }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(g_instance_mutex);
    g_instance_mutex = nullptr;
    return false;
  }
  return true;
}

void OpenUrl(const std::string& url) {
  ShellExecuteW(nullptr, L"open", Widen(url).c_str(), nullptr, nullptr,
      SW_SHOWNORMAL);
}

bool EnsureDesktopShortcut() {
  bool created = false;
  const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  PWSTR desktop = nullptr;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &desktop))) {
    const std::wstring link_path = std::wstring(desktop) + L"\\fptn-vless.lnk";
    if (GetFileAttributesW(link_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
      const std::wstring exe = ExePathW();
      IShellLinkW* link = nullptr;
      if (!exe.empty() &&
          SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr,
              CLSCTX_INPROC_SERVER, IID_IShellLinkW,
              reinterpret_cast<void**>(&link)))) {
        link->SetPath(exe.c_str());
        // Working directory = the exe folder: the logs/ folder appears there.
        std::wstring dir = exe.substr(0, exe.find_last_of(L'\\'));
        link->SetWorkingDirectory(dir.c_str());
        link->SetDescription(L"fptn-vless");
        link->SetIconLocation(exe.c_str(), 0);
        IPersistFile* file = nullptr;
        if (SUCCEEDED(link->QueryInterface(
                IID_IPersistFile, reinterpret_cast<void**>(&file)))) {
          created = SUCCEEDED(file->Save(link_path.c_str(), TRUE));
          file->Release();
        }
        link->Release();
      }
    }
  }
  if (desktop != nullptr) {
    CoTaskMemFree(desktop);
  }
  if (SUCCEEDED(init)) {
    CoUninitialize();
  }
  return created;
}

bool OwnsConsole() {
  if (GetConsoleWindow() == nullptr) {
    return false;
  }
  DWORD processes[4];
  return GetConsoleProcessList(processes, 4) == 1;
}

void HideConsole() {
  if (HWND window = GetConsoleWindow()) {
    ShowWindow(window, SW_HIDE);
  }
}


namespace {

std::wstring RuleName(int port) {
  return L"fptn-vless TCP " + std::to_wstring(port);
}

}  // namespace

FirewallState FirewallRuleState(int port) {
  std::wstring command = L"netsh.exe advfirewall firewall show rule name=\"" +
                         RuleName(port) + L"\"";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
    return FirewallState::kUnknown;
  }
  FirewallState result = FirewallState::kUnknown;
  if (WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0) {
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    result = code == 0 ? FirewallState::kOpen : FirewallState::kClosed;
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return result;
}

std::string AddFirewallRule(int port) {
  if (port < 1 || port > 65535) {
    return "Неверный порт";
  }
  const std::wstring parameters =
      L"advfirewall firewall add rule name=\"" + RuleName(port) +
      L"\" dir=in action=allow protocol=TCP localport=" +
      std::to_wstring(port) + L" profile=any";
  SHELLEXECUTEINFOW info{};
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
  info.lpVerb = L"runas";  // UAC prompt
  info.lpFile = L"netsh.exe";
  info.lpParameters = parameters.c_str();
  info.nShow = SW_HIDE;
  if (!ShellExecuteExW(&info)) {
    return GetLastError() == ERROR_CANCELLED
               ? "Запрос прав администратора отклонён"
               : "Не удалось запустить netsh";
  }
  std::string error;
  if (info.hProcess != nullptr) {
    if (WaitForSingleObject(info.hProcess, 60000) != WAIT_OBJECT_0) {
      error = "netsh не завершился вовремя";
    } else {
      DWORD code = 1;
      GetExitCodeProcess(info.hProcess, &code);
      if (code != 0) {
        error = "netsh вернул ошибку " + std::to_string(code);
      }
    }
    CloseHandle(info.hProcess);
  }
  return error;
}

struct Tray::Impl {
  Callbacks callbacks;
  std::wstring tooltip;
  std::thread thread;
  std::mutex mu;
  std::condition_variable cv;
  bool ready = false;
  bool ok = false;
  std::atomic<HWND> window{nullptr};
  UINT taskbar_created = 0;
  NOTIFYICONDATAW data{};

  static constexpr UINT kTrayMessage = WM_APP + 1;
  static constexpr UINT kOpenId = 1;
  static constexpr UINT kExitId = 2;

  void AddIcon(HWND hwnd) {
    data = NOTIFYICONDATAW{};
    data.cbSize = sizeof(data);
    data.hWnd = hwnd;
    data.uID = 1;
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = kTrayMessage;
// Our own icon from the exe resources (fptn-vless.rc); the stock one if
    // the resource is missing.
    data.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    if (data.hIcon == nullptr) {
      data.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));  // IDI_APPLICATION
    }
    wcsncpy(data.szTip, tooltip.c_str(), sizeof(data.szTip) / sizeof(wchar_t) - 1);
    Shell_NotifyIconW(NIM_ADD, &data);
  }

  void ShowMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kOpenId, L"Открыть панель");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kExitId, L"Выход");
    POINT cursor;
    GetCursorPos(&cursor);
    SetForegroundWindow(hwnd);  // required, or the menu never closes
    const UINT chosen = TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, cursor.x, cursor.y, 0,
        hwnd, nullptr);
    DestroyMenu(menu);
    PostMessageW(hwnd, WM_NULL, 0, 0);
    if (chosen == kOpenId && callbacks.on_open) {
      callbacks.on_open();
    } else if (chosen == kExitId && callbacks.on_exit) {
      callbacks.on_exit();
    }
  }

  static LRESULT CALLBACK WndProc(
      HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
      auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
      SetWindowLongPtrW(hwnd, GWLP_USERDATA,
          reinterpret_cast<LONG_PTR>(create->lpCreateParams));
      return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    if (self != nullptr) {
      if (msg == kTrayMessage) {
        if (lparam == WM_LBUTTONDBLCLK || lparam == WM_LBUTTONUP) {
          if (self->callbacks.on_open) {
            self->callbacks.on_open();
          }
        } else if (lparam == WM_RBUTTONUP) {
          self->ShowMenu(hwnd);
        }
        return 0;
      }
      if (msg == self->taskbar_created && msg != 0) {
        self->AddIcon(hwnd);  // Explorer restarted: put the icon back
        return 0;
      }
      if (msg == WM_CLOSE) {
        Shell_NotifyIconW(NIM_DELETE, &self->data);
        DestroyWindow(hwnd);
        return 0;
      }
      if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
      }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  void Run() {
    const wchar_t* class_name = L"fptn_vless_tray_window";
    WNDCLASSW wc{};
    wc.lpfnWndProc = &Impl::WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = class_name;
    RegisterClassW(&wc);
    taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    HWND hwnd = CreateWindowExW(0, class_name, L"fptn-vless", 0, 0, 0, 0, 0,
        nullptr, nullptr, wc.hInstance, this);
    if (hwnd != nullptr) {
      window = hwnd;
      AddIcon(hwnd);
    }
    {
      const std::lock_guard<std::mutex> lock(mu);
      ok = hwnd != nullptr;
      ready = true;
    }
    cv.notify_all();
    if (hwnd == nullptr) {
      return;
    }
    MSG message;
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
  }
};

Tray::Tray(Callbacks callbacks, std::string tooltip)
    : impl_(std::make_unique<Impl>()) {
  impl_->callbacks = std::move(callbacks);
  impl_->tooltip = Widen(tooltip);
}

Tray::~Tray() { Stop(); }

bool Tray::Start() {
  impl_->thread = std::thread([this]() { impl_->Run(); });
  std::unique_lock<std::mutex> lock(impl_->mu);
  impl_->cv.wait(lock, [this]() { return impl_->ready; });
  return impl_->ok;
}

void Tray::Stop() {
  if (HWND hwnd = impl_->window.load()) {
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
  }
  if (impl_->thread.joinable()) {
    impl_->thread.join();
  }
  impl_->window = nullptr;
}

void Tray::Balloon(const std::string& title, const std::string& text) {
  if (impl_->window.load() == nullptr) {
    return;
  }
  NOTIFYICONDATAW data = impl_->data;
  data.uFlags = NIF_INFO;
  wcsncpy(data.szInfoTitle, Widen(title).c_str(),
      sizeof(data.szInfoTitle) / sizeof(wchar_t) - 1);
  wcsncpy(data.szInfo, Widen(text).c_str(),
      sizeof(data.szInfo) / sizeof(wchar_t) - 1);
  data.dwInfoFlags = NIIF_INFO;
  Shell_NotifyIconW(NIM_MODIFY, &data);
}

}  // namespace fptn::vless::platform

#else  // ------------------------------------------------------- not Windows

namespace fptn::vless::platform {

bool AcquireSingleInstance() { return true; }
void OpenUrl(const std::string&) {}
bool EnsureDesktopShortcut() { return false; }
bool OwnsConsole() { return false; }
void HideConsole() {}
FirewallState FirewallRuleState(int) { return FirewallState::kUnsupported; }
std::string AddFirewallRule(int) { return "Недоступно на этой системе"; }

struct Tray::Impl {};
Tray::Tray(Callbacks, std::string) : impl_(std::make_unique<Impl>()) {}
Tray::~Tray() = default;
bool Tray::Start() { return false; }
void Tray::Stop() {}
void Tray::Balloon(const std::string&, const std::string&) {}

}  // namespace fptn::vless::platform

#endif
