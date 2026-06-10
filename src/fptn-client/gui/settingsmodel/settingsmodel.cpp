/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingsmodel/settingsmodel.h"

#if _WIN32
#include <Windows.h>   // NOLINT(build/include_order)
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <shlobj.h>    // NOLINT(build/include_order)
#elif defined(__linux__)
#include <linux/limits.h>  // NOLINT(build/include_order)
#include <unistd.h>        // NOLINT(build/include_order)
#endif

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QDir>               // NOLINT(build/include_order)
#include <QFile>              // NOLINT(build/include_order)
#include <QJsonArray>         // NOLINT(build/include_order)
#include <QJsonDocument>      // NOLINT(build/include_order)
#include <QJsonObject>        // NOLINT(build/include_order)
#include <QNetworkInterface>  // NOLINT(build/include_order)
#include <QStandardPaths>     // NOLINT(build/include_order)
#include <QTcpSocket>         // NOLINT(build/include_order)

#include "routing//route_manager.h"
#include "utils/brotli/brotli.h"

using fptn::gui::ServerConfig;
using fptn::gui::ServiceConfig;
using fptn::gui::SettingsModel;

namespace {
QVector<ServerConfig> ParseServers(const QJsonArray& servers_array) {
  QVector<ServerConfig> servers;
  for (const auto& server_value : servers_array) {
    const QJsonObject server_obj = server_value.toObject();
    bool status = false;
    auto server = ServerConfig::parse(server_obj, status);
    if (status) {
      servers.push_back(std::move(server));
    } else {
      QString error = QObject::tr(
          "Missing required fields in configuration. Generate and apply a new "
          "token.");
      throw std::runtime_error(error.toStdString());
    }
  }
  return servers;
}

QVector<QString> SplitStringToVector(const QString& str) {
  QVector<QString> result;
  if (str.isEmpty()) {
    return result;
  }
  const auto parts = str.split(',', Qt::SkipEmptyParts);
  for (const auto& part : parts) {
    result.append(part.trimmed());
  }
  return result;
}

QString JoinVectorToString(const QVector<QString>& vec) {
  return vec.join(',');
}

};  // namespace

SettingsModel::SettingsModel(const QMap<QString, QString>& languages,
    const QString& default_language,
    std::size_t ping_thread_pool_size,
    QObject* parent)
    : QObject(parent),
      languages_(languages),
      default_language_(default_language),
      selected_language_(default_language),
      ping_thread_pool_(ping_thread_pool_size),
      ping_timer_(this),
#if _WIN32
      enable_advanced_dns_management_(false),
#endif
      client_autostart_(false),
      enable_split_tunnel_(false) {
#if _WIN32
  wchar_t exe_path[MAX_PATH] = {};
  if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH) != 0) {
    std::filesystem::path exe_dir =
        std::filesystem::path(exe_path).parent_path();
    std::string sni_folder = (exe_dir / "SNI").string();
    sni_manager_ = std::make_shared<SNIManager>(sni_folder);
  } else {
    const auto settings_folder = GetSettingsFolderPath();
    const std::string sni_folder = settings_folder.toStdString() + "/" + "SNI";
    sni_manager_ = std::make_shared<SNIManager>(sni_folder);
  }
#elif __linux__
  char exe_path[PATH_MAX] = {};
  ssize_t count = readlink("/proc/self/exe", exe_path, PATH_MAX);
  if (count != -1) {
    exe_path[count] = '\0';
    std::filesystem::path exe_dir =
        std::filesystem::path(exe_path).parent_path();
    std::string sni_folder = (exe_dir / "SNI").string();
    sni_manager_ = std::make_shared<SNIManager>(sni_folder);
  } else {
    const auto settings_folder = GetSettingsFolderPath();
    const std::string sni_folder = settings_folder.toStdString() + "/" + "SNI";
    sni_manager_ = std::make_shared<SNIManager>(sni_folder);
  }
#else
  const auto settings_folder = GetSettingsFolderPath();
  const std::string sni_folder = settings_folder.toStdString() + "/" + "SNI";
  sni_manager_ = std::make_shared<SNIManager>(sni_folder);
#endif
  Load(true);
}

SettingsModel::~SettingsModel() {
  StopPingMonitoring();

  ping_thread_pool_.stop();
  ping_thread_pool_.join();
}

QString SettingsModel::GetSettingsFilePath() const {
  const QString directory = GetSettingsFolderPath();
  return directory + "/fptn-settings-4.json";
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
QString SettingsModel::GetSettingsFolderPath() const {
#ifdef __APPLE__
  const QString directory =
      QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
#else
  const QString directory =
      QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
#endif
  QDir dir(directory);
  if (!dir.exists()) {
    dir.mkpath(directory);
  }
  return directory;
}

void SettingsModel::Load(bool dont_load_server) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  services_.clear();

  const QString file_path = GetSettingsFilePath();
  QFile file(file_path);
  if (!file.open(QIODevice::ReadOnly)) {
    SPDLOG_WARN("Failed to open file for reading: {}", file_path.toStdString());
    return;
  }

  const QByteArray data = file.readAll();
  file.close();
  const QJsonDocument document = QJsonDocument::fromJson(data);
  const QJsonObject service_obj = document.object();

  if (service_obj.contains("services")) {
    QJsonArray services_array = service_obj["services"].toArray();
    for (const auto& service_value : services_array) {
      QJsonObject jsonservice_obj = service_value.toObject();
      ServiceConfig service;

      service.service_name = jsonservice_obj["service_name"].toString();
      service.username = jsonservice_obj["username"].toString();
      service.password = jsonservice_obj["password"].toString();

      if (!dont_load_server) {
        service.servers = ParseServers(jsonservice_obj["servers"].toArray());
        if (jsonservice_obj.contains("censored_zone_servers")) {
          service.censored_zone_servers =
              ParseServers(jsonservice_obj["censored_zone_servers"].toArray());
        }
      }
      services_.push_back(service);
    }
  }
  if (service_obj.contains("network_interface")) {
    network_interface_ = service_obj["network_interface"].toString();
  }
  if (network_interface_.isEmpty()) {
    network_interface_ = "auto";
  }

  if (service_obj.contains("language")) {
    selected_language_ = service_obj["language"].toString();
  }
  if (service_obj.contains("autostart")) {
    client_autostart_ = service_obj["autostart"].toBool();
  }

#if _WIN32
  if (service_obj.contains("enable_advanced_dns_management")) {
    enable_advanced_dns_management_ =
        service_obj["enable_advanced_dns_management"].toBool();
  }
#endif

  if (service_obj.contains("gateway_ip")) {
    gateway_ip_ = service_obj["gateway_ip"].toString();
  }
  if (gateway_ip_.isEmpty()) {
    gateway_ip_ = "auto";
  }

  if (service_obj.contains("sni")) {
    sni_ = service_obj["sni"].toString();
  }
  if (sni_.isEmpty()) {
    sni_ = FPTN_DEFAULT_SNI;
  }

  if (service_obj.contains("bypass_method")) {
    bypass_method_ = service_obj["bypass_method"].toString();
  }

  // /* Replace DEPRECATED METHODS */
  // if (bypass_method_ == kBypassMethodSni ||
  //     bypass_method_ == kBypassMethodSniReality) {
  //   bypass_method_ = kBypassMethodSniRealityYandex25;
  // }

  if (bypass_method_.isEmpty() ||
      (bypass_method_ != kBypassMethodSni &&
          bypass_method_ != kBypassMethodObfuscation &&
          bypass_method_ != kBypassMethodSniReality &&
          /* Chrome */
          bypass_method_ != kBypassMethodSniRealityChrome149 &&
          bypass_method_ != kBypassMethodSniRealityChrome148 &&
          bypass_method_ != kBypassMethodSniRealityChrome147 &&
          bypass_method_ != kBypassMethodSniRealityChrome146 &&
          bypass_method_ != kBypassMethodSniRealityChrome145 &&
          /* Firefox */
          bypass_method_ != kBypassMethodSniRealityFirefox151 &&
          bypass_method_ != kBypassMethodSniRealityFirefox150 &&
          bypass_method_ != kBypassMethodSniRealityFirefox149 &&
          /* Yandex Browser */
          bypass_method_ != kBypassMethodSniRealityYandex26_4 &&
          bypass_method_ != kBypassMethodSniRealityYandex26_3 &&
          bypass_method_ != kBypassMethodSniRealityYandex25 &&
          bypass_method_ != kBypassMethodSniRealityYandex24 &&
          /* Safari */
          bypass_method_ != kBypassMethodSniRealitySafari26_5 &&
          bypass_method_ != kBypassMethodSniRealitySafari26_4)) {
    bypass_method_ = kBypassMethodSniRealityYandex25;  // BYDEFAULT
  }

  if (service_obj.contains("blacklist_domains")) {
    blacklist_domains_ = service_obj["blacklist_domains"].toString();
  }
  if (blacklist_domains_.isEmpty()) {
    blacklist_domains_ =
        "domain:solovev-live.ru,domain:ria.ru,domain:tass.ru,domain:1tv.ru,"
        "domain:ntv.ru,domain:rt.com";
  }

  if (service_obj.contains("exclude_tunnel_networks")) {
    exclude_tunnel_networks_ =
        service_obj["exclude_tunnel_networks"].toString();
  }
  if (exclude_tunnel_networks_.isEmpty()) {
    exclude_tunnel_networks_ = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
  }

  if (service_obj.contains("include_tunnel_networks")) {
    include_tunnel_networks_ =
        service_obj["include_tunnel_networks"].toString();
  }

  if (service_obj.contains("enable_split_tunnel")) {
    enable_split_tunnel_ = service_obj["enable_split_tunnel"].toBool();
  }

  if (service_obj.contains("split_tunnel_mode")) {
    split_tunnel_mode_ = service_obj["split_tunnel_mode"].toString();
  }
  if (split_tunnel_mode_.isEmpty() ||
      (split_tunnel_mode_ != kSplitTunnelModeExclude &&
          split_tunnel_mode_ != kSplitTunnelModeInclude)) {
    split_tunnel_mode_ = kSplitTunnelModeExclude;
  }

  if (service_obj.contains("split_tunnel_domains")) {
    split_tunnel_domains_ = service_obj["split_tunnel_domains"].toString();
  }
  if (split_tunnel_domains_.isEmpty()) {
    split_tunnel_domains_ =
        "domain:ru,domain:su,domain:рф,domain:vk.com,domain:yandex.com,"
        "domain:userapi.com,domain:yandex.net,domain:clstorage.net";
  }
}

QString SettingsModel::LanguageName() const {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (it.key() == selected_language_) {
      return it.value();
    }
  }
  return "English";
}

const QString& SettingsModel::LanguageCode() const {
  return selected_language_;
}

const QString& SettingsModel::DefaultLanguageCode() const {
  return default_language_;
}

void SettingsModel::SetLanguage(const QString& language_name) {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (language_name == it.value()) {
      selected_language_ = it.key();
    }
  }
  Save();
}

void SettingsModel::SetLanguageCode(const QString& language_code) {
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    if (language_code == it.key()) {
      selected_language_ = language_code;
    }
  }
  Save();
}

QVector<QString> SettingsModel::GetLanguages() const {
  QVector<QString> languages;
  for (auto it = languages_.begin(); it != languages_.end(); ++it) {
    languages.push_back(it.value());
  }
  return languages;
}

bool SettingsModel::ExistsTranslation(const QString& language_code) const {
  return languages_.contains(language_code);
}

bool SettingsModel::Save() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  QString file_path = GetSettingsFilePath();
  QFile file(file_path);
  if (!file.open(QIODevice::WriteOnly)) {
    SPDLOG_ERROR(
        "Failed to open file for writing: {}", file_path.toStdString());
    return false;
  }

  QJsonObject json_object;
  QJsonArray services_array;
  for (const auto& service : services_) {
    QJsonObject service_obj;
    service_obj["service_name"] = service.service_name;
    service_obj["username"] = service.username;
    service_obj["password"] = service.password;

    QJsonArray servers_array;
    for (const auto& server : service.servers) {
      QJsonObject server_obj;
      server_obj["name"] = server.name;
      server_obj["host"] = server.host;
      server_obj["port"] = server.port;
      server_obj["is_using"] = server.is_using;
      server_obj["md5_fingerprint"] = server.md5_fingerprint;
      servers_array.append(server_obj);
    }
    service_obj["servers"] = servers_array;

    QJsonArray censored_zone_servers;
    for (const auto& server : service.censored_zone_servers) {
      QJsonObject server_obj;
      server_obj["name"] = server.name;
      server_obj["host"] = server.host;
      server_obj["port"] = server.port;
      server_obj["is_using"] = server.is_using;
      server_obj["md5_fingerprint"] = server.md5_fingerprint;
      censored_zone_servers.append(server_obj);
    }
    service_obj["censored_zone_servers"] = censored_zone_servers;
    services_array.append(service_obj);
  }

  json_object["language"] = selected_language_;
  json_object["services"] = services_array;
  json_object["network_interface"] = network_interface_;
  json_object["gateway_ip"] = gateway_ip_;
  json_object["autostart"] = client_autostart_ ? 1 : 0;
  json_object["sni"] = sni_;
  json_object["bypass_method"] = bypass_method_;

#if _WIN32
  json_object["enable_advanced_dns_management"] =
      enable_advanced_dns_management_;
#endif

  json_object["blacklist_domains"] = blacklist_domains_;
  json_object["exclude_tunnel_networks"] = exclude_tunnel_networks_;
  json_object["include_tunnel_networks"] = include_tunnel_networks_;
  json_object["enable_split_tunnel"] = enable_split_tunnel_;
  json_object["split_tunnel_mode"] = split_tunnel_mode_;
  json_object["split_tunnel_domains"] = split_tunnel_domains_;

  QJsonDocument document(json_object);
  auto len = file.write(document.toJson());
  file.close();

  emit dataChanged();

  return len > 0;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ServiceConfig SettingsModel::ParseToken(const QString& token) {
  QJsonParseError parse_error;
  const QByteArray token_data = token.toUtf8();
  QJsonDocument json_doc = QJsonDocument::fromJson(token_data, &parse_error);

  if (parse_error.error != QJsonParseError::NoError) {
    throw std::runtime_error(
        "JSON parsing error: " + parse_error.errorString().toStdString());
  }

  QJsonObject json_object = json_doc.object();
  if (!json_object.contains("service_name") ||
      !json_object.contains("username") || !json_object.contains("password") ||
      !json_object.contains("servers")) {
    throw std::runtime_error("Missing required fields in JSON.");
  }
  ServiceConfig service;
  service.service_name = json_object["service_name"].toString();
  service.username = json_object["username"].toString();
  service.password = json_object["password"].toString();

  service.servers = ParseServers(json_object["servers"].toArray());
  if (json_object.contains("censored_zone_servers")) {
    service.censored_zone_servers =
        ParseServers(json_object["censored_zone_servers"].toArray());
  }
  return service;
}

QString SettingsModel::UsingNetworkInterface() const {
  return network_interface_;
}

void SettingsModel::SetUsingNetworkInterface(const QString& iface) {
  network_interface_ = (iface.isEmpty() ? "auto" : iface);
}

QString SettingsModel::GatewayIp() const {
  return gateway_ip_.isEmpty() ? "auto" : gateway_ip_;
}

void SettingsModel::SetGatewayIp(const QString& ip) {
  gateway_ip_ = ip.isEmpty() ? "auto" : ip;
  Save();
}

QString SettingsModel::SNI() const {
  return sni_.isEmpty() ? FPTN_DEFAULT_SNI : sni_;
}

void SettingsModel::SetSNI(const QString& sni) {
  sni_ = sni;
  Save();
}

bool SettingsModel::Autostart() const { return client_autostart_; }

void SettingsModel::SetAutostart(bool value) {
  client_autostart_ = value;
  Save();
}

const QVector<ServiceConfig>& SettingsModel::Services() const {
  return services_;
}

void SettingsModel::AddService(const ServiceConfig& server) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  services_.append(server);
}

void SettingsModel::RemoveServer(int index) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (index >= 0 && index < services_.size()) {
    services_.removeAt(index);
  }
}

void SettingsModel::Clear() { services_.clear(); }

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
QVector<QString> SettingsModel::GetNetworkInterfaces() const {
  QVector<QString> interfaces;
  interfaces.append("auto");

  QList<QNetworkInterface> network_interfaces =
      QNetworkInterface::allInterfaces();

  for (const QNetworkInterface& network_interface : network_interfaces) {
    if (!network_interface.flags().testFlag(QNetworkInterface::IsLoopBack)) {
      const QString iface_name = network_interface.humanReadableName();
      if (!iface_name.isEmpty()) {
        interfaces.append(iface_name);
      }
    }
  }
  return interfaces;
}

int SettingsModel::GetExistServiceIndex(const QString& name) const {
  for (int i = 0; i < services_.size(); i++) {
    if (services_[i].service_name == name) {
      return i;
    }
  }
  return -1;
}

QString SettingsModel::BypassMethod() const {
  return bypass_method_.isEmpty() ? kBypassMethodSni : bypass_method_;
}

void SettingsModel::SetBypassMethod(const QString& method) {
  bypass_method_ = method;
  Save();
}

fptn::gui::SNIManagerSPtr SettingsModel::SniManager() const {
  return sni_manager_;
}

QVector<QString> SettingsModel::BlacklistDomains() const {
  if (blacklist_domains_.isEmpty()) {
    return SplitStringToVector(FPTN_CLIENT_DEFAULT_BLACKLIST_DOMAINS);
  }
  return SplitStringToVector(blacklist_domains_);
}

void SettingsModel::SetBlacklistDomains(const QVector<QString>& domains) {
  blacklist_domains_ = JoinVectorToString(domains);
  Save();
}

QVector<QString> SettingsModel::ExcludeTunnelNetworks() const {
  if (exclude_tunnel_networks_.isEmpty()) {
    return SplitStringToVector(FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS);
  }
  return SplitStringToVector(exclude_tunnel_networks_);
}

void SettingsModel::SetExcludeTunnelNetworks(const QVector<QString>& networks) {
  exclude_tunnel_networks_ = JoinVectorToString(networks);
  Save();
}

QVector<QString> SettingsModel::IncludeTunnelNetworks() const {
  return SplitStringToVector(include_tunnel_networks_);
}

void SettingsModel::SetIncludeTunnelNetworks(const QVector<QString>& networks) {
  include_tunnel_networks_ = JoinVectorToString(networks);
  Save();
}

bool SettingsModel::EnableSplitTunnel() const { return enable_split_tunnel_; }

void SettingsModel::SetEnableSplitTunnel(bool enable) {
  enable_split_tunnel_ = enable;
  Save();
}

QString SettingsModel::SplitTunnelMode() const {
  return split_tunnel_mode_.isEmpty() ? kSplitTunnelModeExclude
                                      : split_tunnel_mode_;
}

void SettingsModel::SetSplitTunnelMode(const QString& mode) {
  split_tunnel_mode_ = mode;
  Save();
}

QVector<QString> SettingsModel::SplitTunnelDomains() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (split_tunnel_domains_.isEmpty()) {
    return SplitStringToVector(FPTN_CLIENT_DEFAULT_SPLIT_TUNNEL_DOMAINS);
  }
  return SplitStringToVector(split_tunnel_domains_);
}

void SettingsModel::SetSplitTunnelDomains(const QVector<QString>& domains) {
  split_tunnel_domains_ = JoinVectorToString(domains);
  Save();
}
#if _WIN32
bool SettingsModel::EnableAdvancedDnsManagement() const {
  return enable_advanced_dns_management_;
}

void SettingsModel::SetEnableAdvancedDnsManagement(const bool enable) {
  enable_advanced_dns_management_ = enable;
}
#endif

void SettingsModel::StartPingMonitoring() {
  const std::unique_lock<std::mutex> lock(mutex_);

  if (start_pinging_) {
    return;
  }

  start_pinging_ = true;
  connect(&ping_timer_, &QTimer::timeout, [this]() {
    if (!start_pinging_ || pending_pings_ > 0) {
      return;
    }

    QSet<QPair<QString, int>> servers_to_check;
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      for (const auto& service : services_) {
        for (const auto& server : service.servers) {
          servers_to_check.insert({server.host, server.port});
        }
        for (const auto& server : service.censored_zone_servers) {
          servers_to_check.insert({server.host, server.port});
        }
      }
    }

    pending_pings_ = servers_to_check.size();

    for (const auto& [host, port] : servers_to_check) {
      boost::asio::post(ping_thread_pool_, [this, host, port]() {
        PingServer(host, port);
        pending_pings_--;
      });
    }
  });

  if (!ping_timer_.isActive()) {
    ping_timer_.start(1000);
  }
}

void SettingsModel::StopPingMonitoring() {
  if (!start_pinging_) {
    return;
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!start_pinging_) {
      return;
    }
    start_pinging_ = false;
  }
}

void SettingsModel::PingServer(const QString& host, int port) {
  std::vector<int> results;

  for (int i = 0; start_pinging_ && i < 3; ++i) {
    const auto start_time = std::chrono::steady_clock::now();
    int ping_ms = -1;

    QTcpSocket socket;
    socket.connectToHost(host, port);
    if (socket.waitForConnected(2000)) {
      const auto end_time = std::chrono::steady_clock::now();
      ping_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
          end_time - start_time)
                    .count();
    }
    socket.close();
    results.push_back(ping_ms);
  }

  const bool has_error =
      std::ranges::any_of(results, [](int ping) { return ping == -1; });

  int final_ping_ms = -1;
  if (!has_error && !results.empty()) {
    const int sum = std::accumulate(results.begin(), results.end(), 0);
    final_ping_ms = sum / static_cast<int>(results.size());
  }

  const std::unique_lock<std::mutex> lock(mutex_);

  if (start_pinging_) {
    for (auto& service : services_) {
      for (auto& server : service.servers) {
        if (server.host == host && server.port == port) {
          server.ping_ms = final_ping_ms;
        }
      }
      for (auto& server : service.censored_zone_servers) {
        if (server.host == host && server.port == port) {
          server.ping_ms = final_ping_ms;
        }
      }
    }
  }
}
