#pragma once

/*
 * Tiny local web page ("mini GUI"): http://127.0.0.1:<port>/
 * Shows the active server, the VLESS link(s), all servers with their response
 * time and the recent events; buttons switch the server, rescan, check the
 * tunnel. Listens on the loopback interface only.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio.hpp>

namespace fptn::vless {

struct DashboardApi {
  std::function<std::string()> state_json;
  // POST /api/<action>?<query> with an optional body. Must return at once.
  // Returns an HTTP status: 202 done/started, 400 bad request, 404 unknown,
  // 409 not possible now (busy).
  std::function<int(const std::string& action,
      const std::string& query,
      const std::string& body)>
      post;
};

class Dashboard {
 public:
  Dashboard(boost::asio::io_context& ioc, std::uint16_t port, DashboardApi api);
  ~Dashboard();

  bool Start();  // false if the port is taken
  void Stop();
  [[nodiscard]] std::uint16_t Port() const { return port_; }

  // Exposed for tests: the response to one request (no sockets).
  std::string Handle(
      const std::string& request_head, const std::string& body = {}) const;

 private:
  void DoAccept();

  boost::asio::io_context& ioc_;
  std::uint16_t port_;
  DashboardApi api_;
  boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace fptn::vless
