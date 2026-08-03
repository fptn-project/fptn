/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/speedwidget/speedwidget.h"

using fptn::gui::SpeedWidget;

namespace {

QString FormatSpeed(std::size_t bytes_per_sec) {
  QString speed_str;
  double bits_per_sec = bytes_per_sec * 8.0;
  if (bits_per_sec >= 1e9) {
    speed_str = QString::asprintf("%.2f Gbps", bits_per_sec / 1e9);
  } else if (bits_per_sec >= 1e6) {
    speed_str = QString::asprintf("%.2f Mbps", bits_per_sec / 1e6);
  } else if (bits_per_sec >= 1e3) {
    speed_str = QString::asprintf("%.2f Kbps", bits_per_sec / 1e3);
  } else {
    speed_str = QString::asprintf("%.2f bps", bits_per_sec);
  }
  if (speed_str.size() >= 20) {
    return speed_str;
  }
  return speed_str.leftJustified(25);
}

QString FormatSpeedLabel(const QString& text, std::size_t speed) {
  return "       " + text + ": " + FormatSpeed(speed);
}

}  // namespace

SpeedWidget::SpeedWidget(QWidget* parent)
    : QWidget(parent),
      connection_time_label_(new QLabel("", this)),
      upload_speed_label_(
          new QLabel(FormatSpeedLabel(QObject::tr("Upload speed"), 0), this)),
      download_speed_label_(new QLabel(
          FormatSpeedLabel(QObject::tr("Download speed"), 0), this)) {
  auto* layout = new QVBoxLayout();
  layout->setContentsMargins(4, 4, 4, 4);
  layout->addWidget(connection_time_label_);
  layout->addWidget(download_speed_label_);
  layout->addWidget(upload_speed_label_);
  setLayout(layout);
}

void SpeedWidget::UpdateSpeed(
    std::size_t upload_speed, std::size_t download_speed) {
  upload_speed_label_->setText(
      FormatSpeedLabel(QObject::tr("Upload speed"), upload_speed));
  download_speed_label_->setText(
      FormatSpeedLabel(QObject::tr("Download speed"), download_speed));
}

void SpeedWidget::UpdateConnectionTime(const QString& time) {
  connection_time_label_->setText(
      " " + QObject::tr("Connection time") + ": " + time);
}