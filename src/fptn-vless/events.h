#pragma once

/*
 * User-visible events ("switched to Finland-2", "new client 192.168.0.5").
 * They always go to the log file; what else happens with them is decided by the
 * front end: the console prints them, a GUI/web page shows them in its list.
 * Library chatter (spdlog) stays out of the console.
 */

#include <chrono>
#include <ctime>
#include <deque>
#include <vector>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::vless {

using EventSink = std::function<void(const std::string& line)>;

namespace detail {
struct EventState {
  std::mutex mu;
  EventSink sink;
  std::deque<std::string> recent;  // "HH:MM:SS text", newest last
};
inline std::string Stamp() {
  const std::time_t now =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &now);
#else
  localtime_r(&now, &local);
#endif
  char buf[16];
  std::strftime(buf, sizeof(buf), "%H:%M:%S", &local);
  return buf;
}
inline EventState& Events() {
  static EventState state;
  return state;
}
}  // namespace detail

// nullptr = events only go to the log file.
inline void SetEventSink(EventSink sink) {
  const std::lock_guard<std::mutex> lock(detail::Events().mu);
  detail::Events().sink = std::move(sink);
}

// The last events (for the dashboard).
inline std::vector<std::string> RecentEvents() {
  const std::lock_guard<std::mutex> lock(detail::Events().mu);
  return {detail::Events().recent.begin(), detail::Events().recent.end()};
}

template <typename... Args>
void Notify(fmt::format_string<Args...> format, Args&&... args) {
  const std::string text = fmt::format(format, std::forward<Args>(args)...);
  SPDLOG_INFO("{}", text);
  const std::string line = detail::Stamp() + " " + text;
  EventSink sink;
  {
    const std::lock_guard<std::mutex> lock(detail::Events().mu);
    auto& recent = detail::Events().recent;
    recent.push_back(line);
    if (recent.size() > 200) {
      recent.pop_front();
    }
    sink = detail::Events().sink;
  }
  if (sink) {
    sink(line);
  }
}

}  // namespace fptn::vless
