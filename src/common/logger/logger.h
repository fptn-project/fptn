/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <clocale>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include <spdlog/sinks/android_sink.h>  // NOLINT(build/include_order)
#elif __APPLE__
#include <TargetConditionals.h>  // NOLINT(build/include_order)
#include <pwd.h>                 // NOLINT(build/include_order)
#include <unistd.h>              // NOLINT(build/include_order)
#elif __linux__
#include <pwd.h>     // NOLINT(build/include_order)
#include <unistd.h>  // NOLINT(build/include_order)
#elif _WIN32
#include <windows.h>
#endif

#include <spdlog/async.h>                     // NOLINT(build/include_order)
#include <spdlog/sinks/rotating_file_sink.h>  // NOLINT(build/include_order)
#include <spdlog/sinks/stdout_color_sinks.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>                    // NOLINT(build/include_order)

namespace fptn::logger {
inline bool init(const std::string& app_name) {
  // Set locale
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  std::ios::sync_with_stdio(false);
  std::wcout.imbue(std::locale(".UTF-8"));
#endif
  std::locale::global(std::locale::classic());
  setlocale(LC_ALL, "en_US.UTF-8");
  try {
#ifdef __ANDROID__
    auto logger = spdlog::android_logger_mt("android", app_name);
#elif TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    // iOS specific logging - use console only since filesystem access is
    // restricted
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>(app_name, console_sink);
    logger->flush_on(spdlog::level::debug);
    spdlog::flush_every(std::chrono::seconds(3));
#else

#ifdef __linux__
    const std::filesystem::path log_dir = "/var/log/fptn/";
#elif defined(__APPLE__) && TARGET_OS_MAC
    const std::filesystem::path log_dir = []() {
      if (const char* home = getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Logs/fptn";
      }
      struct passwd pwd = {};
      struct passwd* result = nullptr;
      char buffer[1024] = {};
      if (getpwuid_r(getuid(), &pwd, buffer, sizeof(buffer), &result) != 0 ||
          !result) {
        throw std::runtime_error("Failed to get user home directory");
      }
      return std::filesystem::path(pwd.pw_dir) / "Library/Logs/fptn";
    }();
#elif _WIN32
    const std::filesystem::path log_dir = "./logs/";
#endif
    const std::filesystem::path log_file = log_dir / (app_name + ".log");
    if (!std::filesystem::exists(log_dir)) {
      try {
        std::filesystem::create_directories(log_dir);
      } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to create log directory: " << e.what() << "\n";
        return false;
      }
    }
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file.string(), 12 * 1024 * 1024, 3, true);
    constexpr std::size_t kLogQueueSize = 32768;
    spdlog::init_thread_pool(kLogQueueSize, 1);
    auto logger = std::make_shared<spdlog::async_logger>(app_name,
        spdlog::sinks_init_list{console_sink, file_sink},
        spdlog::thread_pool(), spdlog::async_overflow_policy::overrun_oldest);
    spdlog::flush_every(std::chrono::seconds(3));
#endif

    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] [%s:%#] %v");

#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    SPDLOG_INFO("Logger initialized for iOS - console output only");
#elif __ANDROID__
    SPDLOG_INFO("Logger inited");
#else
    SPDLOG_INFO("Logging to file: {}", log_file.string());
    SPDLOG_INFO("FPTN version: {}", FPTN_VERSION);
#endif
    return true;
  } catch (const spdlog::spdlog_ex& ex) {
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "FPTN",
        "Logger initialization failed: %s", ex.what());
#else
    std::cerr << "Logger initialization failed: " << ex.what() << "\n";
#endif
  } catch (...) {
    std::cerr << "Unhandled exception caught in logger\n";
  }
  return false;
}
}  // namespace fptn::logger
