#pragma once

/*
 * What the program remembers between runs: the access token (encrypted for
 * the current Windows user with DPAPI), the last chosen server and whether it
 * was picked by hand. Stored in %APPDATA%\fptn-vless\settings.json.
 */

#include <string>

namespace fptn::vless {

struct Settings {
  std::string token;   // empty = nothing saved
  std::string server;  // server name chosen last time, may be empty
  // "best": the fastest server, re-checked all the time.
  // "selected": only the server chosen by the user.
  std::string mode = "best";
  // What to do when the current server stops working.
  bool switch_on_failure = true;
  int port = 0;        // VLESS port chosen in the panel, 0 = default
};

class SettingsStore {
 public:
  explicit SettingsStore(std::string directory);

  static std::string DefaultDirectory();

  Settings Load() const;                 // missing/corrupt file = defaults
  bool Save(const Settings& settings) const;
  void Clear() const;                    // delete the file

  [[nodiscard]] const std::string& Directory() const { return directory_; }

 private:
  std::string FilePath() const;
  std::string directory_;
};

// Exposed for tests.
std::string Base64Encode(const std::string& data);
bool Base64Decode(const std::string& text, std::string& out);

}  // namespace fptn::vless
