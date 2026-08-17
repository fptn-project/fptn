/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/sni_autoscan_dialog/sni_autoscan_dialog.h"

#include <algorithm>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <QApplication>   // NOLINT(build/include_order)
#include <QFontDatabase>  // NOLINT(build/include_order)
#include <QMessageBox>    // NOLINT(build/include_order)
#include <QScrollBar>     // NOLINT(build/include_order)
#include <QTextDocument>  // NOLINT(build/include_order)
#include <QVBoxLayout>    // NOLINT(build/include_order)

#include "common/api/handle.h"

#include "fptn-protocol-lib/https/api_client/api_client.h"

namespace {

QString StatusHtml(bool ok) {
  return ok ? QStringLiteral(R"(<font color="green">YES</font>)")
            : QStringLiteral(R"(<font color="red">NO</font>)");
}

QString FormatLogEntry(const QString& server,
    const QString& sni,
    bool handshake_ok,
    bool http_ok) {
  constexpr int kServerWidth = 22;
  constexpr int kSniWidth = 42;

  QString columns = QStringLiteral("%1%2")
                        .arg(server, -kServerWidth)
                        .arg(sni, -kSniWidth)
                        .toHtmlEscaped();
  columns.replace(QLatin1Char(' '), QLatin1String("&nbsp;"));

  return QStringLiteral("<div>%1Handshake: %2&nbsp;&nbsp;HTTP: %3</div>")
      .arg(columns, StatusHtml(handshake_ok), StatusHtml(http_ok));
}

}  // namespace

namespace fptn::gui {

struct SniAutoscanDialog::ScanContext {
  std::mutex mutex;

  /* set before the workers start, read-only afterwards */
  std::vector<std::string> sni_list;
  QVector<ServerConfig> servers;

  /* guarded by mutex */
  std::size_t next_index = 0;
  std::string found_sni;
  std::deque<QString> pending_log;

  std::atomic<bool> stop{false};
  std::atomic<int> tested{0};
  std::atomic<int> active_workers{0};
};

SniAutoscanDialog::SniAutoscanDialog(SettingsModelPtr settings, QWidget* parent)
    : QDialog(parent), settings_(std::move(settings)) {
  SetupUi();
}

SniAutoscanDialog::~SniAutoscanDialog() {
  if (ctx_) {
    ctx_->stop = true;
  }
}

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
    StopScanning();
    reject();
  });

  top_layout->addWidget(server_combo_box_);
  top_layout->addWidget(sni_file_combo_box_);
  top_layout->addWidget(progress_label_);
  top_layout->addWidget(start_stop_button_);
  top_layout->addWidget(close_button_);

  constexpr int kMaxLogLines = 2000;

  log_text_edit_ = new QTextEdit(this);
  log_text_edit_->setReadOnly(true);
  log_text_edit_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
  log_text_edit_->document()->setMaximumBlockCount(kMaxLogLines);
  QFont log_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  log_font.setPointSize(8);
  log_text_edit_->setFont(log_font);
  connect(log_text_edit_->verticalScrollBar(), &QScrollBar::rangeChanged, this,
      [this](int min, int max) {
        (void)min;
        if (auto_scroll_ && ctx_) {
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
  if (!ctx_) {
    StartScanning();
  } else {
    StopScanning();
  }
}

void SniAutoscanDialog::onUpdateProgress() {
  if (!ctx_) {
    return;
  }

  FlushLog();

  progress_label_->setText(
      QString("%1/%2").arg(ctx_->tested.load()).arg(ctx_->sni_list.size()));

  std::string found;
  {
    const std::unique_lock<std::mutex> lock(ctx_->mutex);
    found = ctx_->found_sni;
  }

  const bool all_workers_done = (ctx_->active_workers == 0);
  if (found.empty() && !all_workers_done) {
    return;
  }

  StopScanning();

  if (!found.empty()) {
    settings_->SetSNI(QString::fromStdString(found));
    settings_->Save();

    QMessageBox::information(this, QObject::tr("Scan completed"),
        QObject::tr("Working SNI found: %1")
            .arg(QString::fromStdString(found)));
  } else {
    QMessageBox::information(this, QObject::tr("Scan completed"),
        QObject::tr("No working SNI found."));
  }
}

void SniAutoscanDialog::StartScanning() {
  std::vector<std::string> sni_vector;
  if (sni_file_combo_box_->currentText() == QObject::tr("All")) {
    sni_vector = CollectAllSni();
  } else {
    sni_vector = CollectSniFromSelectedFile();
  }

  if (sni_vector.empty()) {
    QMessageBox::warning(this, QObject::tr("Error"),
        QObject::tr("No SNI available for scanning."));
    return;
  }

  auto target_servers = CollectTargetServers();
  if (target_servers.isEmpty()) {
    QMessageBox::warning(this, QObject::tr("Error"),
        QObject::tr("No servers available for scanning."));
    return;
  }

  std::random_device rd;
  std::mt19937 g(rd());
  std::ranges::shuffle(sni_vector, g);

  ctx_ = std::make_shared<ScanContext>();
  ctx_->sni_list = std::move(sni_vector);
  ctx_->servers = std::move(target_servers);

  start_stop_button_->setText(QObject::tr("Cancel"));
  server_combo_box_->setEnabled(false);
  sni_file_combo_box_->setEnabled(false);
  progress_label_->setText("0/0");

  constexpr int kThreadCount = 8;
  ctx_->active_workers = kThreadCount;
  for (int i = 0; i < kThreadCount; ++i) {
    /* every thread keeps its own share of the context alive */
    std::thread([ctx = ctx_]() { SniAutoscanDialog::WorkerThread(ctx); })
        .detach();
  }
  progress_timer_->start(100);
}

void SniAutoscanDialog::StopScanning() {
  if (!ctx_) return;

  FlushLog();

  /* The workers own the context, so there is nothing to wait for here: they
   * drop out on the next stop check and release it. */
  ctx_->stop = true;
  ctx_.reset();

  progress_timer_->stop();

  start_stop_button_->setText(QObject::tr("Start"));
  server_combo_box_->setEnabled(true);
  sni_file_combo_box_->setEnabled(true);
}

void SniAutoscanDialog::FlushLog() {
  std::deque<QString> pending;
  {
    const std::unique_lock<std::mutex> lock(ctx_->mutex);
    pending.swap(ctx_->pending_log);
  }

  if (pending.empty()) {
    return;
  }

  QString html;
  for (const auto& entry : pending) {
    html += entry;
  }

  log_text_edit_->moveCursor(QTextCursor::End);
  log_text_edit_->insertHtml(html);
}

void SniAutoscanDialog::WorkerThread(const ScanContextPtr& ctx) {
  while (!ctx->stop) {
    std::string sni;
    {
      const std::unique_lock<std::mutex> lock(ctx->mutex);
      if (ctx->next_index >= ctx->sni_list.size()) {
        break;
      }
      sni = ctx->sni_list[ctx->next_index++];
    }

    bool sni_works = false;

    for (const auto& server : ctx->servers) {
      if (ctx->stop) {
        break;
      }

      bool http_ok = false;

      constexpr int kHandshakeTimeout = 2;
      fptn::protocol::https::ApiClient client(server.host.toStdString(),
          server.port, sni, server.md5_fingerprint.toStdString(),
          protocol::https::CensorshipStrategy::kSni);

      const bool handshake_ok = client.TestHandshake(kHandshakeTimeout);
      if (handshake_ok) {
        constexpr int kHttpTimeout = 5;
        const auto response = client.Get(common::api::kApiDnsUrl, kHttpTimeout);
        http_ok = (response.code == 200);

        if (http_ok) {
          sni_works = true;
        }
      }

      {
        const std::unique_lock<std::mutex> lock(ctx->mutex);
        ctx->pending_log.push_back(FormatLogEntry(server.name,
            QString::fromStdString(sni), handshake_ok, http_ok));
      }

      if (sni_works) {
        break;
      }
    }

    ++ctx->tested;

    if (sni_works) {
      {
        const std::unique_lock<std::mutex> lock(ctx->mutex);
        if (ctx->found_sni.empty()) {
          ctx->found_sni = sni;
        }
      }
      ctx->stop = true;
      break;
    }
  }

  --ctx->active_workers;
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

}  // namespace fptn::gui
