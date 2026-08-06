/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/translations/translations.h"

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QApplication>   // NOLINT(build/include_order)
#include <QFontDatabase>  // NOLINT(build/include_order)
#include <QTranslator>    // NOLINT(build/include_order)

#include "common/logger/logger.h"

namespace {

QTranslator& getTranslator() {
  static QTranslator translator;
  return translator;
}

struct PersianFontState {
  QString family;
  QString original_style;
  QString applied_language;
  bool loaded = false;
  bool style_saved = false;
};

PersianFontState& getFontState() {
  static PersianFontState state;
  return state;
}

void loadPersianFont() {
  PersianFontState& state = getFontState();
  if (state.loaded) {
    return;
  }
  state.loaded = true;

  const char* const k_font_paths[] = {
      ":/fonts/Vazirmatn-Regular.ttf",
      ":/fonts/Vazirmatn-Medium.ttf",
      ":/fonts/Vazirmatn-Bold.ttf",
  };
  for (const char* path : k_font_paths) {
    const int id = QFontDatabase::addApplicationFont(path);
    if (id == -1) {
      SPDLOG_ERROR("Failed to load font: {}", path);
      continue;
    }
    const QStringList families = QFontDatabase::applicationFontFamilies(id);
    SPDLOG_INFO("Loaded font '{}': families=[{}]", path,
        families.join(", ").toStdString());
    if (state.family.isEmpty() && !families.isEmpty()) {
      state.family = families.first();
    }
  }
}

}  // namespace

bool fptn::gui::SetTranslation(const QString& language_code) {
  PersianFontState& state = getFontState();

  // setStyleSheet() re-styles all widgets — skip if language hasn't changed.
  if (language_code == state.applied_language) {
    return true;
  }
  state.applied_language = language_code;

  const QString translation_file = QString("fptn_%1.qm").arg(language_code);
  QTranslator& translator = getTranslator();
  qApp->removeTranslator(&translator);

  if (language_code == "fa") {
    loadPersianFont();

    if (!state.style_saved) {
      state.original_style = qApp->styleSheet();
      state.style_saved = true;
    }

    const QString font_name =
        state.family.isEmpty() ? "Vazirmatn" : state.family;

    qApp->setLayoutDirection(Qt::RightToLeft);
    qApp->setFont(QFont(font_name, 10));

    // Stylesheet forces Vazirmatn on all widgets; setFont() is overridden by
    // stylesheet on some platforms.
    qApp->setStyleSheet(
        state.original_style + "\n" +
        QString("QWidget { font-family: '%1'; font-size: 10pt; }")
            .arg(font_name));

    const QFont check(font_name);
    if (check.exactMatch()) {
      SPDLOG_INFO(
          "Persian font '{}' applied successfully", font_name.toStdString());
    } else {
      SPDLOG_WARN("Persian font '{}' not exact, actual fallback: '{}'",
          font_name.toStdString(), qApp->font().family().toStdString());
    }
  } else {
    if (state.style_saved) {
      qApp->setStyleSheet(state.original_style);
    }
    qApp->setLayoutDirection(Qt::LeftToRight);
    qApp->setFont(QFont());
  }

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
