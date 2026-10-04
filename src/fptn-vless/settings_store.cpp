#include "fptn-vless/settings_store.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dpapi.h>  // after windows.h
#else
#include <sys/stat.h>
#endif

namespace fptn::vless {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Protects/unprotects the token. Windows: DPAPI, bound to the logged-in user.
// Elsewhere (tests only): stored as is.
bool Protect(const std::string& plain, std::string& out) {
#ifdef _WIN32
  DATA_BLOB in{static_cast<DWORD>(plain.size()),
      reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))};
  DATA_BLOB blob{};
  if (!CryptProtectData(&in, L"fptn-vless token", nullptr, nullptr, nullptr,
          CRYPTPROTECT_UI_FORBIDDEN, &blob)) {
    return false;
  }
  out.assign(reinterpret_cast<char*>(blob.pbData), blob.cbData);
  LocalFree(blob.pbData);
  return true;
#else
  out = plain;
  return true;
#endif
}

bool Unprotect(const std::string& protected_data, std::string& out) {
#ifdef _WIN32
  DATA_BLOB in{static_cast<DWORD>(protected_data.size()),
      reinterpret_cast<BYTE*>(const_cast<char*>(protected_data.data()))};
  DATA_BLOB blob{};
  if (!CryptUnprotectData(
          &in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &blob)) {
    return false;
  }
  out.assign(reinterpret_cast<char*>(blob.pbData), blob.cbData);
  LocalFree(blob.pbData);
  return true;
#else
  out = protected_data;
  return true;
#endif
}

}  // namespace

std::string Base64Encode(const std::string& data) {
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 2 < data.size(); i += 3) {
    const unsigned v = (static_cast<unsigned char>(data[i]) << 16) |
                       (static_cast<unsigned char>(data[i + 1]) << 8) |
                       static_cast<unsigned char>(data[i + 2]);
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += kAlphabet[v & 63];
  }
  if (i + 1 == data.size()) {
    const unsigned v = static_cast<unsigned char>(data[i]) << 16;
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += "==";
  } else if (i + 2 == data.size()) {
    const unsigned v = (static_cast<unsigned char>(data[i]) << 16) |
                       (static_cast<unsigned char>(data[i + 1]) << 8);
    out += kAlphabet[(v >> 18) & 63];
    out += kAlphabet[(v >> 12) & 63];
    out += kAlphabet[(v >> 6) & 63];
    out += '=';
  }
  return out;
}

bool Base64Decode(const std::string& text, std::string& out) {
  out.clear();
  unsigned buffer = 0;
  int bits = 0;
  for (const char c : text) {
    if (c == '=') {
      break;
    }
    const char* pos = nullptr;
    for (const char* p = kAlphabet; *p != '\0'; ++p) {
      if (*p == c) {
        pos = p;
        break;
      }
    }
    if (pos == nullptr) {
      return false;
    }
    buffer = (buffer << 6) | static_cast<unsigned>(pos - kAlphabet);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += static_cast<char>((buffer >> bits) & 0xFF);
    }
  }
  return true;
}

SettingsStore::SettingsStore(std::string directory)
    : directory_(std::move(directory)) {}

std::string SettingsStore::DefaultDirectory() {
#ifdef _WIN32
  if (const char* appdata = std::getenv("APPDATA")) {
    return (std::filesystem::path(appdata) / "fptn-vless").string();
  }
  return "./fptn-vless-settings";
#else
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
    return (std::filesystem::path(xdg) / "fptn-vless").string();
  }
  if (const char* home = std::getenv("HOME")) {
    return (std::filesystem::path(home) / ".config" / "fptn-vless").string();
  }
  return "./fptn-vless-settings";
#endif
}

std::string SettingsStore::FilePath() const {
  return (std::filesystem::path(directory_) / "settings.json").string();
}

Settings SettingsStore::Load() const {
  Settings settings;
  try {
    std::ifstream file(FilePath(), std::ios::binary);
    if (!file) {
      return settings;
    }
    const auto json = nlohmann::json::parse(
        std::string(std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()));
    if (json.contains("token") && json["token"].is_string()) {
      std::string raw;
      std::string plain;
      if (Base64Decode(json["token"].get<std::string>(), raw) &&
          Unprotect(raw, plain)) {
        settings.token = plain;
      }
    }
    if (json.contains("server") && json["server"].is_string()) {
      settings.server = json["server"].get<std::string>();
    }
    if (json.contains("mode") && json["mode"].is_string()) {
      const auto mode = json["mode"].get<std::string>();
      settings.mode = mode == "selected" ? "selected" : "best";
    } else if (json.contains("pinned") && json["pinned"].is_boolean()) {
      settings.mode = json["pinned"].get<bool>() ? "selected" : "best";  // old file
    }
    if (json.contains("switch_on_failure") &&
        json["switch_on_failure"].is_boolean()) {
      settings.switch_on_failure = json["switch_on_failure"].get<bool>();
    }
    if (json.contains("port") && json["port"].is_number_integer()) {
      const int port = json["port"].get<int>();
      settings.port = (port >= 1 && port <= 65535) ? port : 0;
    }
  } catch (...) {  // corrupt file = start from scratch
    return Settings{};
  }
  return settings;
}

bool SettingsStore::Save(const Settings& settings) const {
  try {
    std::filesystem::create_directories(directory_);
    nlohmann::json json;
    std::string protected_token;
    if (!settings.token.empty()) {
      if (!Protect(settings.token, protected_token)) {
        return false;
      }
      json["token"] = Base64Encode(protected_token);
    }
    json["server"] = settings.server;
    json["mode"] = settings.mode;
    json["switch_on_failure"] = settings.switch_on_failure;
    json["port"] = settings.port;
    const std::string tmp = FilePath() + ".tmp";
    {
      std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
      if (!file) {
        return false;
      }
      file << json.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
      if (!file.good()) {
        return false;
      }
    }
#ifndef _WIN32
    chmod(tmp.c_str(), 0600);  // the token is a credential
#endif
    std::filesystem::rename(tmp, FilePath());
    return true;
  } catch (...) {
    return false;
  }
}

void SettingsStore::Clear() const {
  std::error_code ec;
  std::filesystem::remove(FilePath(), ec);
}

}  // namespace fptn::vless
