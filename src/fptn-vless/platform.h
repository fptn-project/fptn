#pragma once

/*
 * The few Windows-only conveniences: one running instance, a tray icon, a
 * desktop shortcut, opening the browser, hiding our own console window.
 * On other systems everything is a harmless no-op (so tests build anywhere).
 */

#include <functional>
#include <memory>
#include <string>

namespace fptn::vless::platform {

// false = another copy of the program is already running.
bool AcquireSingleInstance();

// Opens the URL in the default browser.
void OpenUrl(const std::string& url);

// Creates "fptn-vless" on the desktop unless it is already there.
// True only if a shortcut was created just now.
bool EnsureDesktopShortcut();

// True if the console window belongs to this program alone (started by
// double-click or from a shortcut, not from the user's own terminal).
bool OwnsConsole();
void HideConsole();

// Windows firewall: lets phones and other PCs in the LAN reach the VLESS port.
enum class FirewallState { kUnsupported, kUnknown, kOpen, kClosed };
FirewallState FirewallRuleState(int port);
// Adds an inbound TCP allow rule. Needs administrator rights, so Windows shows
// its UAC prompt. Blocks until done. Empty string = success, else the reason.
std::string AddFirewallRule(int port);

class Tray {
 public:
  struct Callbacks {
    std::function<void()> on_open;  // icon clicked / "Open" chosen
    std::function<void()> on_exit;  // "Exit" chosen
  };

  Tray(Callbacks callbacks, std::string tooltip);
  ~Tray();
  Tray(const Tray&) = delete;
  Tray& operator=(const Tray&) = delete;

  bool Start();
  void Stop();
  void Balloon(const std::string& title, const std::string& text);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fptn::vless::platform
