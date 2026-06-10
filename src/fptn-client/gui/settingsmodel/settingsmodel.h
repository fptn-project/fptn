/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <QFile>          // NOLINT(build/include_order)
#include <QJsonArray>     // NOLINT(build/include_order)
#include <QJsonDocument>  // NOLINT(build/include_order)
#include <QJsonObject>    // NOLINT(build/include_order)
#include <QMap>           // NOLINT(build/include_order)
#include <QMutex>         // NOLINT(build/include_order)
#include <QObject>        // NOLINT(build/include_order)
#include <QString>        // NOLINT(build/include_order)
#include <QTimer>         // NOLINT(build/include_order)
#include <QVector>        // NOLINT(build/include_order)

#include "gui/sni_manager/sni_manager.h"

namespace fptn::gui {
/*
{
    "gateway_ip": "auto",
    "language": "en",
    "network_interface": "auto",
    "services": [
        {
            "version": 2,
            "service_name": "FPTN.ONLINE",
            "username": "test",
            "password": "test",
            "servers": [
                    {
                        "name": "pq1",
                        "host": "74.119.195.151",
                        "md5_fingerprint": "5c903603cbcfbf0601193c4cc859292c",
                        "port": 443
                    }
                ],
            "censored_zone_servers": [
                    {
                        "name": "Server1",
                        "host": "127.0.0.1",
                        "port": 443,
                        "md5_fingerprint": "5c903603cbcfbf0601193c4cc859292c"
                    }
                ]
            }
        }
    ],
    "blacklist_domains":
"domain:solovev-live.ru,domain:ria.ru,domain:tass.ru,domain:1tv.ru,domain:ntv.ru,domain:rt.com",
    "exclude_tunnel_networks": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    "include_tunnel_networks": "",
    "enable_split_tunnel": true,
    "split_tunnel_mode": "exclude",
    "split_tunnel_domains":
"domain:ru,domain:su,domain:рф,domain:vk.com,domain:yandex.com,domain:userapi.com,domain:yandex.net,domain:clstorage.net"
}
*/

struct ServerConfig {
  QString name;
  QString host;
  int port;
  bool is_using;
  QString md5_fingerprint;
  int ping_ms = -1;

  static ServerConfig parse(const QJsonObject& server_obj, bool& status) {
    status = false;
    if (!server_obj.contains("name") || !server_obj.contains("host") ||
        !server_obj.contains("port") ||
        !server_obj.contains("md5_fingerprint")) {
      return {};
    }
    ServerConfig server = {};
    server.name = server_obj["name"].toString();
    server.host = server_obj["host"].toString();
    server.port = server_obj["port"].toInt();
    server.md5_fingerprint = server_obj["md5_fingerprint"].toString();
    server.is_using = true;
    server.ping_ms = -1;
    status = true;
    return server;
  }
};

struct ServiceConfig {
  QString service_name;
  QString username;
  QString password;
  QVector<ServerConfig> servers;
  QVector<ServerConfig> censored_zone_servers;
  QString language;
};

class SettingsModel : public QObject {
  Q_OBJECT

 public:
  static constexpr const char* kSplitTunnelModeExclude = "exclude";
  static constexpr const char* kSplitTunnelModeInclude = "include";

  // DEPRECATED
  static constexpr const char* kBypassMethodSni = "SNI";

  static constexpr const char* kBypassMethodObfuscation = "OBFUSCATION";

  // DEPRECATED
  static constexpr const char* kBypassMethodSniReality = "SNI-REALITY";

  /* chrome */
  static constexpr const char* kBypassMethodSniRealityChrome149 =
      "SNI-REALITY-CHROME-149";
  static constexpr const char* kBypassMethodSniRealityChrome148 =
      "SNI-REALITY-CHROME-148";
  static constexpr const char* kBypassMethodSniRealityChrome147 =
      "SNI-REALITY-CHROME-147";
  static constexpr const char* kBypassMethodSniRealityChrome146 =
      "SNI-REALITY-CHROME-146";
  static constexpr const char* kBypassMethodSniRealityChrome145 =
      "SNI-REALITY-CHROME-145";
  /* Firefox */
  static constexpr const char* kBypassMethodSniRealityFirefox151 =
      "SNI-REALITY-FIREFOX-151";
  static constexpr const char* kBypassMethodSniRealityFirefox150 =
      "SNI-REALITY-FIREFOX-150";
  static constexpr const char* kBypassMethodSniRealityFirefox149 =
      "SNI-REALITY-FIREFOX-149";
  /* Yandex Browser */
  static constexpr const char* kBypassMethodSniRealityYandex26_4 =
      "SNI-REALITY-YANDEX-26-4";
  static constexpr const char* kBypassMethodSniRealityYandex26_3 =
      "SNI-REALITY-YANDEX-26-3";
  static constexpr const char* kBypassMethodSniRealityYandex25 =
      "SNI-REALITY-YANDEX-25";
  static constexpr const char* kBypassMethodSniRealityYandex24 =
      "SNI-REALITY-YANDEX-24";
  /* Safari */
  static constexpr const char* kBypassMethodSniRealitySafari26_5 =
      "SNI-REALITY-SAFARI-26-5";
  static constexpr const char* kBypassMethodSniRealitySafari26_4 =
      "SNI-REALITY-SAFARI-26-4";

 public:
  explicit SettingsModel(const QMap<QString, QString>& languages,
      const QString& default_language = "en",
      std::size_t ping_thread_pool_size = 4,
      QObject* parent = nullptr);

  ~SettingsModel() override;

  void Load(bool dont_load_server = false);
  bool Save();

  void StartPingMonitoring();
  void StopPingMonitoring();

  QString UsingNetworkInterface() const;

  void SetUsingNetworkInterface(const QString&);

  QString GatewayIp() const;
  void SetGatewayIp(const QString& ip);

  QString SNI() const;
  void SetSNI(const QString& sni);

  QVector<QString> GetNetworkInterfaces() const;

  const QVector<ServiceConfig>& Services() const;
  void AddService(const ServiceConfig& server);
  void RemoveServer(int index);
  int GetExistServiceIndex(const QString& name) const;
  ServiceConfig ParseToken(const QString& token);
  void Clear();

  QString LanguageName() const;
  void SetLanguage(const QString& language);
  void SetLanguageCode(const QString& language_code);

  QVector<QString> GetLanguages() const;

  const QString& DefaultLanguageCode() const;
  const QString& LanguageCode() const;

  bool ExistsTranslation(const QString& language_code) const;

  bool Autostart() const;
  void SetAutostart(bool value);

  QString GetSettingsFilePath() const;
  QString GetSettingsFolderPath() const;

  QString BypassMethod() const;
  void SetBypassMethod(const QString& method);

  SNIManagerSPtr SniManager() const;

  QVector<QString> BlacklistDomains() const;
  void SetBlacklistDomains(const QVector<QString>& domains);

  QVector<QString> ExcludeTunnelNetworks() const;
  void SetExcludeTunnelNetworks(const QVector<QString>& networks);

  QVector<QString> IncludeTunnelNetworks() const;
  void SetIncludeTunnelNetworks(const QVector<QString>& networks);

  bool EnableSplitTunnel() const;
  void SetEnableSplitTunnel(bool enable);

  QString SplitTunnelMode() const;
  void SetSplitTunnelMode(const QString& mode);

  QVector<QString> SplitTunnelDomains();
  void SetSplitTunnelDomains(const QVector<QString>& domains);

#if _WIN32
  bool EnableAdvancedDnsManagement() const;
  void SetEnableAdvancedDnsManagement(bool enable);
#endif

 protected:
  void PingServer(const QString& host, int port);

 signals:
  void dataChanged();

 private:
  std::mutex mutex_;

  QMap<QString, QString> languages_;

  QString default_language_;

  QString selected_language_;

  boost::asio::thread_pool ping_thread_pool_;
  QTimer ping_timer_;
  std::atomic<bool> start_pinging_{false};
  std::atomic<int> pending_pings_{0};

  QVector<ServiceConfig> services_;
  QString network_interface_;
  QString gateway_ip_;
  QString sni_;

#if _WIN32
  bool enable_advanced_dns_management_;
#endif
  bool client_autostart_;

  QString bypass_method_;

  QString blacklist_domains_;
  QString exclude_tunnel_networks_;
  QString include_tunnel_networks_;
  bool enable_split_tunnel_;
  QString split_tunnel_mode_;
  QString split_tunnel_domains_;

  SNIManagerSPtr sni_manager_;
};

using SettingsModelPtr = std::shared_ptr<SettingsModel>;
}  // namespace fptn::gui
