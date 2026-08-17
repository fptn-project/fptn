/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <QComboBox>    // NOLINT(build/include_order)
#include <QDialog>      // NOLINT(build/include_order)
#include <QLabel>       // NOLINT(build/include_order)
#include <QPushButton>  // NOLINT(build/include_order)
#include <QTextEdit>    // NOLINT(build/include_order)
#include <QTimer>       // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"
#include "gui/settingsmodel/settingsmodel.h"

namespace fptn::gui {

class SniAutoscanDialog : public QDialog {
  Q_OBJECT

 public:
  explicit SniAutoscanDialog(
      SettingsModelPtr settings, QWidget* parent = nullptr);
  ~SniAutoscanDialog() override;

  // cppcheck-suppress unknownMacro
 public slots:
  void onStartStopClicked();
  void onUpdateProgress();

 protected:
  /* Scan state is owned by the worker threads, so the dialog can be closed
   * without waiting for the network operations still in flight. */
  struct ScanContext;
  using ScanContextPtr = std::shared_ptr<ScanContext>;

  void SetupUi();

  void StartScanning();
  void StopScanning();
  void FlushLog();

  static void WorkerThread(const ScanContextPtr& ctx);

  std::vector<std::string> CollectAllSni() const;
  std::vector<std::string> CollectSniFromSelectedFile() const;
  QVector<ServerConfig> CollectTargetServers() const;

 private:
  ScanContextPtr ctx_;

  SettingsModelPtr settings_;

  QComboBox* server_combo_box_ = nullptr;
  QComboBox* sni_file_combo_box_ = nullptr;
  QLabel* progress_label_ = nullptr;
  QPushButton* start_stop_button_ = nullptr;
  QPushButton* close_button_ = nullptr;
  QTextEdit* log_text_edit_ = nullptr;
  QTimer* progress_timer_ = nullptr;

  bool auto_scroll_ = true;
};

}  // namespace fptn::gui
