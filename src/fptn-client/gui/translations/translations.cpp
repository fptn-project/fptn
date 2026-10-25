/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/translations/translations.h"

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QApplication>  // NOLINT(build/include_order)
#include <QLocale>       // NOLINT(build/include_order)
#include <QTranslator>   // NOLINT(build/include_order)

#include "common/logger/logger.h"

namespace {
QTranslator& getTranslator() {
  static QTranslator translator;
  return translator;
}
}  // namespace

bool fptn::gui::SetTranslation(const QString& language_code) {
  if (language_code == "fa") {
    qApp->setLayoutDirection(Qt::RightToLeft);
    QLocale::setDefault(QLocale(QLocale::Persian, QLocale::Iran));
  } else {
    qApp->setLayoutDirection(Qt::LeftToRight);
    QLocale::setDefault(QLocale::system());
  }

  const QString translation_file = QString("fptn_%1.qm").arg(language_code);
  QTranslator& translator = getTranslator();
  qApp->removeTranslator(&translator);
  if (translator.load(translation_file, ":/translations")) {
    if (!qApp->installTranslator(&translator)) {
      SPDLOG_WARN("Failed to install translator for language: {}",
          language_code.toStdString());
    } else {
      return true;
    }
  } else {
    SPDLOG_WARN(
        "Translation file not found: {}", translation_file.toStdString());
  }
  return false;
}