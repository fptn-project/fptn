/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/sni_autoscan_dialog/sni_autoscan_dialog.h"

#include <algorithm>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <QApplication>   // NOLINT(build/include_order)
#include <QFontDatabase>  // NOLINT(build/include_order)
#include <QMessageBox>    // NOLINT(build/include_order)
#include <QScrollBar>     // NOLINT(build/include_order)
#include <QVBoxLayout>    // NOLINT(build/include_order)

#include "common/api/handle.h"

#include "fptn-protocol-lib/https/api_client/api_client.h"

namespace fptn::gui {

SniAutoscanDialog::SniAutoscanDialog(SettingsModelPtr settings, QWidget* parent)
    : QDialog(parent), settings_(std::move(settings)) {
  SetupUi();
}

SniAutoscanDialog::~SniAutoscanDialog() { StopScanning(); }

void SniAutoscanDialog::SetupUi() {
  setMinimumSize(650, 400);
  setWindowTitle(QObject::tr("Autoscan SNI"));
  setModal(true);

  auto* main_layout = new QVBoxLayout(this);
  main_layout->setSpacing(3);
  main_layout->setContentsMargins(3, 3, 3, 3);

  auto* top_layout = new QHBoxLayout(this);
  top_layout->setAlignment(Qt::AlignVCenter);

  server_combo_box_ = new QComboBox(this);
  server_combo_box_->addItem(QObject::tr("All"));
  const QVector<ServiceConfig>& services = settings_->Services();
  for (const auto& service : services) {
    for (const auto& server : service.servers) {
      server_combo_box_->addItem(server.name);
    }
    for (const auto& server : service.censored_zone_servers) {
      server_combo_box_->addItem("* " + server.name);
    }
  }

  sni_file_combo_box_ = new QComboBox(this);
  sni_file_combo_box_->addItem(QObject::tr("All"));
  auto sni_files = settings_->SniManager()->SniFileList();
  for (const auto& file : sni_files) {
    sni_file_combo_box_->addItem(QString::fromStdString(file));
  }

  progress_label_ = new QLabel("0/0", this);
  progress_label_->setMinimumWidth(80);
  progress_label_->setAlignment(Qt::AlignCenter);

  start_stop_button_ = new QPushButton(QObject::tr("Start"), this);
  connect(start_stop_button_, &QPushButton::clicked, this,
      &SniAutoscanDialog::onStartStopClicked);

  close_button_ = new QPushButton(QObject::tr("Close"), this);
  connect(close_button_, &QPushButton::clicked, this, [this]() {
    if (is_scanning_) {
      StopScanning();
    }
    reject();
  });

  top_layout->addWidget(server_combo_box_);
  top_layout->addWidget(sni_file_combo_box_);
  top_layout->addWidget(progress_label_);
  top_layout->addWidget(start_stop_button_);
  top_layout->addWidget(close_button_);

  log_text_edit_ = new QTextEdit(this);
  log_text_edit_->setReadOnly(true);
  log_text_edit_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
  QFont log_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  log_font.setPointSize(8);
  log_text_edit_->setFont(log_font);
  connect(log_text_edit_->verticalScrollBar(), &QScrollBar::rangeChanged, this,
      [this](int min, int max) {
        (void)min;
        if (auto_scroll_ && is_scanning_) {
          log_text_edit_->verticalScrollBar()->setValue(max);
        }
      });
  connect(log_text_edit_->verticalScrollBar(), &QScrollBar::valueChanged, this,
      [this](int value) {
        auto_scroll_ =
            (value == log_text_edit_->verticalScrollBar()->maximum());
      });

  main_layout->addLayout(top_layout);
  main_layout->addWidget(log_text_edit_, 1);

  progress_timer_ = new QTimer(this);
  connect(progress_timer_, &QTimer::timeout, this,
      &SniAutoscanDialog::onUpdateProgress);
}

void SniAutoscanDialog::onStartStopClicked() {
  if (!is_scanning_) {
    StartScanning();
  } else {
    StopScanning();
  }
}

void SniAutoscanDialog::onUpdateProgress() {
  if (!is_scanning_) {
    return;
  }

  const auto total = sni_vector_.size();
  const auto tested = static_cast<std::size_t>(tested_count_);

  if (total > 0) {
    progress_label_->setText(QString("%1/%2").arg(tested).arg(total));
  } else {
    progress_label_->setText("0/0");
  }

  if (working_sni_found_ > 0 && !found_working_sni_.empty()) {
    StopScanning();

    settings_->SetSNI(QString::fromStdString(found_working_sni_));
    settings_->Save();

    QMessageBox::information(this, QObject::tr("Scan completed"),
        QObject::tr("Working SNI found: %1")
            .arg(QString::fromStdString(found_working_sni_)));
    return;
  }

  if (static_cast<std::size_t>(tested_count_) >= sni_vector_.size()) {
    StopScanning();
    if (working_sni_found_ == 0) {
      QMessageBox::information(this, QObject::tr("Scan completed"),
          QObject::tr("No working SNI found."));
    }
  }
}

void SniAutoscanDialog::StartScanning() {
  if (sni_file_combo_box_->currentText() == QObject::tr("All")) {
    sni_vector_ = CollectAllSni();
  } else {
    sni_vector_ = CollectSniFromSelectedFile();
  }

  if (sni_vector_.empty()) {
    QMessageBox::warning(this, QObject::tr("Error"),
        QObject::tr("No SNI available for scanning."));
    return;
  }

  target_servers_ = CollectTargetServers();
  if (target_servers_.isEmpty()) {
    QMessageBox::warning(this, QObject::tr("Error"),
        QObject::tr("No servers available for scanning."));
    return;
  }

  std::random_device rd;
  std::mt19937 g(rd());
  std::ranges::shuffle(sni_vector_, g);

  is_scanning_ = true;
  stop_requested_ = false;
  tested_count_ = 0;
  working_sni_found_ = 0;
  current_sni_index_ = 0;
  found_working_sni_.clear();

  start_stop_button_->setText(QObject::tr("Cancel"));
  server_combo_box_->setEnabled(false);
  sni_file_combo_box_->setEnabled(false);
  progress_label_->setText("0/0");

  constexpr int kThreadCount = 8;
  for (int i = 0; i < kThreadCount; ++i) {
    worker_threads_.emplace_back(&SniAutoscanDialog::WorkerThread, this, i);
  }
  progress_timer_->start(100);
}

void SniAutoscanDialog::StopScanning() {
  if (!is_scanning_) return;

  stop_requested_ = true;

  for (auto& thread : worker_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  worker_threads_.clear();

  is_scanning_ = false;
  progress_timer_->stop();

  start_stop_button_->setText(QObject::tr("Start"));
  server_combo_box_->setEnabled(true);
  sni_file_combo_box_->setEnabled(true);
}

std::string SniAutoscanDialog::GetNextSni() {
  const std::unique_lock<std::mutex> lock(mutex_);

  if (current_sni_index_ >= sni_vector_.size()) {
    return std::string();
  }
  return sni_vector_[current_sni_index_++];
}

void SniAutoscanDialog::WorkerThread(int thread_id) {
  (void)thread_id;

  while (!stop_requested_) {
    std::string sni = GetNextSni();
    if (sni.empty()) {
      break;
    }

    bool sni_works = false;

    for (const auto& server : target_servers_) {
      if (stop_requested_) {
        break;
      }

      bool handshake_ok = false;
      bool http_ok = false;

      constexpr int kHandshakeTimeout = 2;
      // SNI reachability probe: no keyed session-id marker here (the shared
      // secret is service-level and not carried by this diagnostic scanner).
      fptn::protocol::https::ApiClient client(server.host.toStdString(),
          server.port, sni, server.md5_fingerprint.toStdString(),
          /*session_key=*/"", protocol::https::CensorshipStrategy::kSni);

      handshake_ok = client.TestHandshake(kHandshakeTimeout);
      if (handshake_ok) {
        constexpr int kHttpTimeout = 5;
        const auto response = client.Get(common::api::kApiDnsUrl, kHttpTimeout);
        http_ok = (response.code == 200);

        if (http_ok) {
          sni_works = true;
        }
      }

      AddLogEntry(
          server.name, QString::fromStdString(sni), handshake_ok, http_ok);

      if (sni_works) {
        break;
      }
    }

    ++tested_count_;

    if (sni_works) {
      found_working_sni_ = sni;
      ++working_sni_found_;
      break;
    }
  }
}

std::vector<std::string> SniAutoscanDialog::CollectAllSni() const {
  std::vector<std::string> all_sni;

  auto files = settings_->SniManager()->SniFileList();
  for (const auto& file : files) {
    auto sni_list = settings_->SniManager()->GetSniList(file);
    for (const auto& sni : sni_list) {
      all_sni.push_back(sni);
    }
  }

  return all_sni;
}

std::vector<std::string> SniAutoscanDialog::CollectSniFromSelectedFile() const {
  std::vector<std::string> sni_list;

  QString selected_file = sni_file_combo_box_->currentText();
  if (selected_file != QObject::tr("All")) {
    sni_list = settings_->SniManager()->GetSniList(selected_file.toStdString());
  }

  return sni_list;
}

QVector<ServerConfig> SniAutoscanDialog::CollectTargetServers() const {
  QVector<ServerConfig> servers;
  QString selected = server_combo_box_->currentText();

  const QVector<ServiceConfig>& services = settings_->Services();

  if (selected == QObject::tr("All")) {
    for (const auto& service : services) {
      for (const auto& server : service.servers) {
        servers.append(server);
      }
      for (const auto& server : service.censored_zone_servers) {
        servers.append(server);
      }
    }
  } else {
    for (const auto& service : services) {
      for (const auto& server : service.servers) {
        if (server.name == selected) {
          servers.append(server);
          break;
        }
      }

      // specific servers
      QString clean_name = selected;
      if (clean_name.startsWith("* ")) {
        clean_name = clean_name.mid(2);
      }
      for (const auto& server : service.censored_zone_servers) {
        if (server.name == clean_name) {
          servers.append(server);
          break;
        }
      }
    }
  }
  return servers;
}

void SniAutoscanDialog::AddLogEntry(const QString& server,
    const QString& sni,
    bool handshake_ok,
    bool http_ok) {
  QMetaObject::invokeMethod(this, [this, server, sni, handshake_ok, http_ok]() {
    const QString handshake_status =
        handshake_ok ? QString("<font color=\"green\">YES</font>")
                     : QString("<font color=\"red\">NO</font>");

    const QString http_status =
        http_ok ? QString("<font color=\"green\">YES</font>")
                : QString("<font color=\"red\">NO</font>");

    const QString log_entry = QString(R"(
        <table style="width: 100%; font-family: monospace; table-layout: fixed; font-size: 9px;">
            <tr>
                <td width="25%" style="white-space: nowrap;">%1</td>
                <td width="45%" style="white-space: nowrap;">%2</td>
                <td width="15%">Handshake: %3</td>
                <td width="15%" style="padding-left: 10px;">HTTP: %4</td>
            </tr>
        </table>
    )")
                                  .arg(server.toHtmlEscaped())
                                  .arg(sni.toHtmlEscaped())
                                  .arg(handshake_status)
                                  .arg(http_status);

    {
      const std::unique_lock<std::mutex> lock(mutex_);

      constexpr int kMaxLogSize = 2048;

      if (log_text_edit_->document()->lineCount() > kMaxLogSize) {
        QTextCursor cursor(log_text_edit_->document());
        cursor.movePosition(QTextCursor::Start);
        cursor.select(QTextCursor::LineUnderCursor);
        cursor.removeSelectedText();
      }

      log_text_edit_->moveCursor(QTextCursor::End);
      log_text_edit_->insertHtml(log_entry);

      QTextCursor cursor(log_text_edit_->textCursor());
      cursor.movePosition(QTextCursor::End);
      log_text_edit_->setTextCursor(cursor);
    }
  });
}

}  // namespace fptn::gui
