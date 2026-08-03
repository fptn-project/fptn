/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QHBoxLayout>  // NOLINT(build/include_order)
#include <QLabel>       // NOLINT(build/include_order)
#include <QStyle>       // NOLINT(build/include_order)
#include <QVBoxLayout>  // NOLINT(build/include_order)
#include <QWidget>      // NOLINT(build/include_order)

namespace fptn::gui {
class SpeedWidget : public QWidget {
  Q_OBJECT

 public:
  explicit SpeedWidget(QWidget* parent = nullptr);
  void UpdateSpeed(std::size_t upload_speed, std::size_t download_speed);
  void UpdateConnectionTime(const QString& time);

 private:
  QLabel* connection_time_label_;
  QLabel* upload_speed_label_;
  QLabel* download_speed_label_;
};

}  // namespace fptn::gui
