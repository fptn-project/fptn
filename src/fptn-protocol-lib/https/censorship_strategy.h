/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

namespace fptn::protocol::https {
enum class CensorshipStrategy : int {
  kSni = 0,
  kTlsObfuscator = 1,
  kSniRealityMode = 2,
  /* Chrome */
  kSniRealityModeChrome145 = 20,
  kSniRealityModeChrome146 = 21,
  kSniRealityModeChrome147 = 22,
  kSniRealityModeChrome148 = 23,
  kSniRealityModeChrome149 = 24,
  /* Firefox */
  kSniRealityModeFirefox149 = 60,
  kSniRealityModeFirefox150 = 61,
  kSniRealityModeFirefox151 = 62,
  /* Yandex Browser */
  kSniRealityModeYandex24 = 80,
  kSniRealityModeYandex25 = 81,
  kSniRealityModeYandex26_3 = 82,
  kSniRealityModeYandex26_4 = 83,
  /* Safari */
  kSniRealityModeSafari26_4 = 100,
  kSniRealityModeSafari26_5 = 101
};

inline std::string ToString(const CensorshipStrategy& strategy) {
  switch (strategy) {
    case CensorshipStrategy::kSni:
      return "SNI";
    case CensorshipStrategy::kTlsObfuscator:
      return "TLS Obfuscation";
    case CensorshipStrategy::kSniRealityMode:
      return "SNI-Reality";
    case CensorshipStrategy::kSniRealityModeChrome145:
      return "Chrome 145";
    case CensorshipStrategy::kSniRealityModeChrome146:
      return "Chrome 146";
    case CensorshipStrategy::kSniRealityModeChrome147:
      return "Chrome 147";
    case CensorshipStrategy::kSniRealityModeChrome148:
      return "Chrome 148";
    case CensorshipStrategy::kSniRealityModeChrome149:
      return "Chrome 149";
    case CensorshipStrategy::kSniRealityModeFirefox149:
      return "Firefox 149";
    case CensorshipStrategy::kSniRealityModeFirefox150:
      return "Firefox 150";
    case CensorshipStrategy::kSniRealityModeFirefox151:
      return "Firefox 151";
    case CensorshipStrategy::kSniRealityModeYandex24:
      return "Yandex 24";
    case CensorshipStrategy::kSniRealityModeYandex25:
      return "Yandex 25";
    case CensorshipStrategy::kSniRealityModeYandex26_3:
      return "Yandex 26.3";
    case CensorshipStrategy::kSniRealityModeYandex26_4:
      return "Yandex 26.4";
    case CensorshipStrategy::kSniRealityModeSafari26_4:
      return "Safari 26.4";
    case CensorshipStrategy::kSniRealityModeSafari26_5:
      return "Safari 26.5";
    default:
      return "Unknown";
  }
}

inline bool IsRealityModeWithFakeHandshake(const CensorshipStrategy& strategy) {
  return strategy == CensorshipStrategy::kSniRealityMode ||
         strategy == CensorshipStrategy::kSniRealityModeChrome149 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome148 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome147 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome146 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome145 ||
         strategy == CensorshipStrategy::kSniRealityModeFirefox151 ||
         strategy == CensorshipStrategy::kSniRealityModeFirefox150 ||
         strategy == CensorshipStrategy::kSniRealityModeFirefox149 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex26_4 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex26_3 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex25 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex24 ||
         strategy == CensorshipStrategy::kSniRealityModeSafari26_5 ||
         strategy == CensorshipStrategy::kSniRealityModeSafari26_4;
}

}  // namespace fptn::protocol::https
