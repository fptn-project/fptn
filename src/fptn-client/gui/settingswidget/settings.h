/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QToolButton>
#include <QWidget>

#include "gui/settingsmodel/settingsmodel.h"

namespace fptn::gui {
class SettingsWidget : public QDialog {
  Q_OBJECT

 public:
  explicit SettingsWidget(SettingsModelPtr settings, QWidget* parent = nullptr);

 protected:
  void closeEvent(QCloseEvent* event) override;

 protected:
  void SetupUi();
  void FillBypassMethodComboBox();
  void UpdateSniFilesList();
  void UpdateServerTableVisibility();

  // cppcheck-suppress unknownMacro
 private slots:
  void onExit();
  void onLoadNewConfig();
  void onRemoveServer(int row);
  void onLanguageChanged(const QString& new_language);
  void onInterfaceChanged(const QString& new_language);
  void onAutostartChanged(bool checked);
  void onAutoGatewayChanged(bool checked);
  void onAutoCustomDnsChanged(bool checked);
  void onBypassMethodChanged(const QString& method);

  // cppcheck-suppress unknownMacro
 private slots:
  void onImportSniFile();
  void onAutoscanClicked();

 private:
  SettingsModelPtr settings_;

  QTabWidget* tab_widget_ = nullptr;
  QWidget* settings_tab_ = nullptr;
  QWidget* routing_tab_ = nullptr;
  QWidget* about_tab_ = nullptr;
  QTableWidget* server_table_ = nullptr;

// AUTOSTART (show only for Linux)
#ifdef __linux__
  QLabel* autostart_label_ = nullptr;
  QCheckBox* autostart_checkbox_ = nullptr;
#endif
  QLabel* language_label_ = nullptr;
  QComboBox* language_combo_box_ = nullptr;

  QGridLayout* grid_layout_ = nullptr;
  QGridLayout* routing_grid_layout_ = nullptr;

  QToolButton* advanced_routing_button_ = nullptr;
  QVector<QWidget*> advanced_routing_widgets_;

  QComboBox* interface_combo_box_ = nullptr;
  QLabel* interface_label_ = nullptr;

  QLineEdit* gateway_line_edit_ = nullptr;
  QCheckBox* gateway_auto_checkbox_ = nullptr;
  QLabel* gateway_label_ = nullptr;

  QLabel* custom_dns_label_ = nullptr;
  QCheckBox* custom_dns_auto_checkbox_ = nullptr;
  QLineEdit* custom_dns_line_edit_ = nullptr;

  QLabel* connection_strategy_label_ = nullptr;
  QComboBox* connection_strategy_combo_box_ = nullptr;

  QLabel* bypass_method_label_ = nullptr;
  QComboBox* bypass_method_combo_box_ = nullptr;

  QHBoxLayout* sni_buttons_layout_ = nullptr;

  QLabel* sni_label_ = nullptr;
  QLineEdit* sni_line_edit_ = nullptr;

  QListWidget* sni_files_list_widget_ = nullptr;
  QPushButton* sni_import_button_ = nullptr;
  QPushButton* sni_autoscan_button_ = nullptr;

  // New fields widgets for routing tab
  QLabel* enable_dns_management_label_ = nullptr;
  QLabel* enable_dns_management_info_label_ = nullptr;
  QCheckBox* enable_dns_management_checkbox_ = nullptr;

  QLabel* enable_ad_block_label_ = nullptr;
  QCheckBox* enable_ad_block_checkbox_ = nullptr;
  QLabel* enable_kill_switch_label_ = nullptr;
  QCheckBox* enable_kill_switch_checkbox_ = nullptr;

  QLabel* blacklist_domains_label_ = nullptr;
  QLabel* blacklist_domains_info_label_ = nullptr;
  QTextEdit* blacklist_domains_text_edit_ = nullptr;

  QLabel* exclude_tunnel_networks_label_ = nullptr;
  QLabel* exclude_tunnel_networks_info_label_ = nullptr;
  QTextEdit* exclude_tunnel_networks_text_edit_ = nullptr;

  QLabel* include_tunnel_networks_label_ = nullptr;
  QLabel* include_tunnel_networks_info_label_ = nullptr;
  QTextEdit* include_tunnel_networks_text_edit_ = nullptr;

  QLabel* enable_split_tunnel_label_ = nullptr;
  QLabel* enable_split_tunnel_info_label_ = nullptr;
  QCheckBox* enable_split_tunnel_checkbox_ = nullptr;

  QLabel* split_tunnel_mode_label_ = nullptr;
  QLabel* split_tunnel_mode_info_label_ = nullptr;
  QComboBox* split_tunnel_mode_combo_box_ = nullptr;

  QLabel* split_tunnel_domains_label_ = nullptr;
  QLabel* split_tunnel_domains_info_label_ = nullptr;
  QTextEdit* split_tunnel_domains_text_edit_ = nullptr;

  QPushButton* load_new_token_button_ = nullptr;

  QPushButton* exit_button_ = nullptr;

  QLabel* version_label_ = nullptr;

  QLabel* project_info_label_ = nullptr;
  QLabel* website_link_label_ = nullptr;
  QLabel* telegram_group_label_ = nullptr;
  QLabel* boosty_link_label_ = nullptr;
  QLabel* sponsors_label_ = nullptr;
  QLabel* sponsors_names_label_ = nullptr;
};
}  // namespace fptn::gui
