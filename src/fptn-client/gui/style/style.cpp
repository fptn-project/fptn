/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/style/style.h"

#include <algorithm>

#include <QFontDatabase>  // NOLINT(build/include_order)
#include <QStringList>    // NOLINT(build/include_order)

namespace fptn::gui {

QFont GetCyrillicCapableFont() {
  static const QStringList kPreferredFamilies = {"Ubuntu", "DejaVu Sans",
      "Liberation Sans", "Noto Sans", "FreeSans", "Cantarell", "Arial"};

  const auto preferred =
      std::ranges::find_if(kPreferredFamilies, [](const QString& family) {
        return QFontDatabase::writingSystems(family).contains(
            QFontDatabase::Cyrillic);
      });
  if (preferred != kPreferredFamilies.cend()) {
    return QFont(*preferred);
  }

  const QFont system_font =
      QFontDatabase::systemFont(QFontDatabase::GeneralFont);
  if (QFontDatabase::writingSystems(system_font.family())
          .contains(QFontDatabase::Cyrillic)) {
    return system_font;
  }

  const QStringList cyrillic_families =
      QFontDatabase::families(QFontDatabase::Cyrillic);
  const auto usable =
      std::ranges::find_if(cyrillic_families, [](const QString& family) {
        return !QFontDatabase::isPrivateFamily(family) &&
               !QFontDatabase::isFixedPitch(family);
      });
  if (usable != cyrillic_families.cend()) {
    return QFont(*usable);
  }
  return system_font;
}

QString GetMacStyleSheet() {
  static const QString kStyleSheet = R"(
QMenu {
    background-color: #333;
    color: #fff;
    border: 1px solid #555;
}
QMenu::item {
    background-color: #333;
    color: #fff;
    padding: 5px 5px;
}
QMenu::item:selected {
    background-color: #555;
    color: #fff;
}
QMenu::icon {
    margin-right: 4px;
}
QAction {
    padding: 2px 2px;
    color: #fff;
}
QWidgetAction {
    padding: 5px;
}
)";
  return kStyleSheet;
}

QString GetUbuntuStyleSheet() {
  static const QString kStyleSheetTemplate = R"(
QMenu {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 8px;
    padding: 5px;
}
QMenu::item {
    background-color: #ffffff;
    color: #333333;
    padding: 2px 3px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
    color: #333333;
}
QMenu::item:hover {
    background-color: #e0e0e0;
}
QMenu::icon {
    margin-right: 4px;
}
QAction {
    color: #333333;
}
QWidgetAction {
    padding: 2px 4px;
}
QWidget {
    font-family: '%1';
    font-size: 10pt;
    color: #333333;
    background-color: #f0f0f0;
}
QPushButton {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    padding: 6px 12px;
}
QPushButton:hover {
    background-color: #e0e0e0;
}
QPushButton:pressed {
    background-color: #d0d0d0;
}
QLineEdit, QTextEdit {
    background-color: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    padding: 4px 8px;
}
QCheckBox, QRadioButton {
    color: #333333;
}
QSlider::groove:horizontal {
    border: 1px solid #d0d0d0;
    height: 8px;
    background: #ffffff;
    border-radius: 4px;
}
QSlider::handle:horizontal {
    background: #333333;
    border: 1px solid #d0d0d0;
    width: 16px;
    border-radius: 4px;
}
QScrollBar:vertical {
    border: 1px solid #d0d0d0;
    background: #ffffff;
    width: 16px;
}
QScrollBar::handle:vertical {
    background: #c0c0c0;
    min-height: 20px;
    border-radius: 8px;
}
QTabBar::tab {
    background: #e0e0e0;
    color: #333333;
    padding: 6px 12px;
    border: 1px solid #d0d0d0;
    border-bottom: 1px solid #ffffff;
    border-radius: 4px 4px 0 0;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #333333;
    border: 1px solid #d0d0d0;
    border-bottom: 1px solid #ffffff;
    border-radius: 4px 4px 0 0;
    font-weight: bold;
}
QTabBar::tab:!selected {
    background: #f0f0f0;
}
QTabWidget::pane {
    border: 1px solid #d0d0d0;
    border-radius: 4px;
    background: #ffffff;
}
QMenu::item:disabled {
    background-color: #ffffff;
    color: #a0a0a0;
}
QAction:disabled {
    color: #a0a0a0;
}
)";
  return kStyleSheetTemplate.arg(GetCyrillicCapableFont().family());
}

QString GetWindowsStyleSheet() {
  static const QString kStyleSheet = R"(
QMenu {
    background-color: #ffffff;
    color: #000000;
    border: 1px solid #bfbfbf;
    border-radius: 4px;
    padding: 5px;
}
QPushButton {
    padding: 6px 12px;
}
QMenu::item {
    background-color: #ffffff;
    color: #000000;
    padding: 2px 1px;
    border-radius: 3px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
    color: #000000;
}
QMenu::item:hover {
    background-color: #e0e0e0;
}
QMenu::icon {
    margin-right: 4px;
}
QAction {
    color: #000000;
}
QMenu QWidget {
    background-color: #ffffff;
    color: #000000;
    border: none;
    padding: 1px 4px;
}
QMenu::item:disabled {
    background-color: #ffffff;
    color: #a0a0a0;
}
QAction:disabled {
    color: #a0a0a0;
}

)";
  return kStyleSheet;
}

}  // namespace fptn::gui
