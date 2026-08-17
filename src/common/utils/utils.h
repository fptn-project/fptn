/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <cstring>
#include <ctime>
#include <random>
#include <ranges>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/locale.hpp>

namespace fptn::common::utils {

inline void GenerateRandomBytes(std::uint8_t* buffer, std::size_t length) {
  thread_local std::mt19937 gen{std::random_device {}()};
  std::uniform_int_distribution<std::uint64_t> dist;

  std::size_t i = 0;
  for (; i + 8 <= length; i += 8) {
    const std::uint64_t rand_val = dist(gen);
    std::memcpy(buffer + i, &rand_val, 8);
  }
  if (i < length) {
    const std::uint64_t rand_val = dist(gen);
    std::memcpy(buffer + i, &rand_val, length - i);
  }
}

inline std::string GenerateRandomString(const int length) {
  static constexpr char kCharacters[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static constexpr std::size_t kCharCount = sizeof(kCharacters) - 1;

  thread_local std::mt19937 gen{std::random_device {}()};
  thread_local std::uniform_int_distribution<std::size_t> dist(
      0, kCharCount - 1);

  std::string result(length, '\0');
  for (int i = 0; i < length; ++i) {
    result[i] = kCharacters[dist(gen)];
  }
  return result;
}

inline std::string RemoveSubstring(
    std::string input, const std::vector<std::string>& strs) {
  for (const auto& substr : strs) {
    boost::algorithm::erase_all(input, substr);
  }
  return input;
}

inline std::string Trim(const std::string& str) {
  auto is_space = [](const unsigned char c) { return std::isspace(c); };

  const auto start = std::ranges::find_if_not(str, is_space);
  const auto end =
      std::ranges::find_if_not(str | std::views::reverse, is_space).base();

  return (start < end) ? std::string(start, end) : std::string();
}

inline std::vector<std::string> SplitCommaSeparated(const std::string& input) {
  std::vector<std::string> result;
  std::stringstream ss(input);
  std::string item;

  while (std::getline(ss, item, ',')) {
    const std::string trimmed = Trim(item);
    if (!trimmed.empty()) {
      result.push_back(trimmed);
    }
  }
  return result;
}

inline std::string ToLowerCase(const std::string& str) {
  try {
    // Generating the locale costs ~45us, so it must not happen per call.
    static const std::locale kLocale = boost::locale::generator()("");
    return boost::locale::to_lower(str, kLocale);
  } catch (...) {
    return str;
  }
  return str;
}

}  // namespace fptn::common::utils
