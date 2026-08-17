/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#if _WIN32
#include <VersionHelpers.h>  // NOLINT(build/include_order)
#endif

#include <string>
#include <vector>

#include <boost/process.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/io.hpp>
#include <boost/process/v1/search_path.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#if _WIN32
#include <boost/process/v1/windows.hpp>
#endif

namespace fptn::common::system::command {

inline bool run(const std::string& command) {
  try {
    SPDLOG_INFO("Running: {}", command);
#ifdef _WIN32
    boost::process::v1::child child(command,
        boost::process::v1::std_out > stdout,
        boost::process::v1::std_err > stderr,
        ::boost::process::v1::windows::hide);
#elif defined(__linux__) || defined(__APPLE__)
    boost::process::v1::child child(command,
        boost::process::v1::std_out > stdout,
        boost::process::v1::std_err > stderr);
#endif
    child.wait();
    return child.exit_code() == 0;
  } catch (const std::exception& e) {
    const std::string msg = e.what();
    SPDLOG_ERROR("Command error: {}  CMD: '{}' ", msg, command);
  } catch (...) {
    SPDLOG_ERROR("Command error: undefined error CMD: '{}' ", command);
  }
  return false;
}

inline bool run_batch(const std::vector<std::string>& commands) {
  bool ok = true;
  for (const auto& cmd : commands) {
    if (cmd.empty()) {
      continue;
    }
    ok = run(cmd) && ok;
  }
  return ok;
}

inline bool run(
    const std::string& command, std::vector<std::string>& std_output) {
  try {
    boost::process::v1::ipstream pipe;
#ifdef _WIN32
    boost::process::v1::child child(command, boost::process::v1::std_out > pipe,
        ::boost::process::v1::windows::hide);
#elif defined(__linux__) || defined(__APPLE__)
    boost::process::v1::child child(boost::process::v1::search_path("bash"),
        "-c", command, boost::process::v1::std_out > pipe);
#endif
    std::string line;
    while (std::getline(pipe, line)) {
      std_output.emplace_back(line);
    }
    child.wait();
    return child.exit_code() == 0;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR(
        "Error: failed to run command '{}'. Error: {}", command, ex.what());
  }
  return false;
}

}  // namespace fptn::common::system::command
