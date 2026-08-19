/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <QFont>
#include <QString>

namespace fptn::gui {

QString GetMacStyleSheet();
QString GetUbuntuStyleSheet();
QString GetWindowsStyleSheet();

QFont GetCyrillicCapableFont();

}  // namespace fptn::gui
