// The control page: routing and the two guards (Host header, CSRF header),
// plus one real HTTP exchange over a socket.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include <boost/asio.hpp>

#include "fptn-vless/dashboard.h"

using namespace fptn::vless;
namespace asio = boost::asio;
using asio::ip::tcp;

static int g_fail = 0;
#define CHECK(cond, msg)                                         \
  do {                                                           \
    if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fail; }  \
    else { std::printf("  ok:   %s\n", msg); }                    \
  } while (0)

static bool Has(const std::string& s, const std::string& part) {
  return s.find(part) != std::string::npos;
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  std::string last_action, last_query, last_body;
  int answer = 202;
  DashboardApi api;
  api.state_json = []() { return std::string("{\"ok\":true}"); };
  api.post = [&](const std::string& action, const std::string& query,
                 const std::string& body) {
    last_action = action;
    last_query = query;
    last_body = body;
    return answer;
  };

  asio::io_context ioc;
  const std::uint16_t port = 18901;
  Dashboard d(ioc, port, api);

  const std::string host = "Host: 127.0.0.1:18901\r\n";
  const std::string post_ok = host + "X-Requested-With: fptn\r\n\r\n";

  std::puts("[1] routing");
  CHECK(Has(d.Handle("GET / HTTP/1.1\r\n" + host + "\r\n"), "200 OK") &&
            Has(d.Handle("GET / HTTP/1.1\r\n" + host + "\r\n"), "<title>fptn-vless"),
      "GET / serves the page");
  CHECK(Has(d.Handle("GET /api/state HTTP/1.1\r\n" + host + "\r\n"), "{\"ok\":true}"),
      "GET /api/state returns the state");
  CHECK(Has(d.Handle("GET /nope HTTP/1.1\r\n" + host + "\r\n"), "404"), "unknown path: 404");
  CHECK(Has(d.Handle("DELETE / HTTP/1.1\r\n" + host + "\r\n"), "405"), "other methods: 405");

  std::puts("[2] actions");
  CHECK(Has(d.Handle("POST /api/connect?i=7 HTTP/1.1\r\n" + post_ok), "202") &&
            last_action == "connect" && last_query == "i=7",
      "POST /api/connect?i=7 reaches the handler");
  CHECK(Has(d.Handle("POST /api/token?remember=1 HTTP/1.1\r\n" + post_ok, "fptnb:abc"), "202") &&
            last_action == "token" && last_body == "fptnb:abc",
      "the body (token) is passed on");
  answer = 409;
  CHECK(Has(d.Handle("POST /api/rescan HTTP/1.1\r\n" + post_ok), "409"), "busy -> 409");
  answer = 400;
  CHECK(Has(d.Handle("POST /api/connect?i=x HTTP/1.1\r\n" + post_ok), "400"), "bad request -> 400");
  answer = 404;
  CHECK(Has(d.Handle("POST /api/nope HTTP/1.1\r\n" + post_ok), "404"), "unknown action -> 404");
  CHECK(Has(d.Handle("POST /other HTTP/1.1\r\n" + post_ok), "404"), "POST outside /api/ -> 404");
  answer = 202;

  std::puts("[3] guards");
  last_action.clear();
  CHECK(Has(d.Handle("POST /api/connect?i=1 HTTP/1.1\r\n" + host + "\r\n"), "403") && last_action.empty(),
      "POST without X-Requested-With is refused (CSRF)");
  CHECK(Has(d.Handle("GET / HTTP/1.1\r\nHost: evil.example:18901\r\n\r\n"), "403"),
      "foreign Host header is refused (DNS rebinding)");
  CHECK(Has(d.Handle("GET / HTTP/1.1\r\n\r\n"), "403"), "missing Host header is refused");
  CHECK(!Has(d.Handle("GET / HTTP/1.1\r\nhost: LOCALHOST:18901\r\n\r\n"), "403"),
      "localhost:port is accepted, case-insensitive");

  std::puts("[4] real socket");
  CHECK(d.Start(), "listens on 127.0.0.1");
  std::thread io([&] { ioc.run(); });
  {
    asio::io_context cio;
    tcp::socket s(cio);
    s.connect({asio::ip::make_address("127.0.0.1"), port});
    const std::string req = "GET /api/state HTTP/1.1\r\n" + host + "Connection: close\r\n\r\n";
    asio::write(s, asio::buffer(req));
    std::string resp;
    boost::system::error_code ec;
    asio::read(s, asio::dynamic_buffer(resp), ec);
    CHECK(Has(resp, "200 OK") && Has(resp, "{\"ok\":true}"), "full request/response over TCP");
  }
  {
    asio::io_context cio;
    tcp::socket s(cio);
    s.connect({asio::ip::make_address("127.0.0.1"), port});
    const std::string big(200000, 'x');  // a huge token, sent in pieces
    const std::string req = "POST /api/token?remember=0 HTTP/1.1\r\n" + host +
        "X-Requested-With: fptn\r\nContent-Length: " + std::to_string(big.size()) +
        "\r\nConnection: close\r\n\r\n";
    asio::write(s, asio::buffer(req));
    for (std::size_t off = 0; off < big.size(); off += 30000) {
      asio::write(s, asio::buffer(big.data() + off, std::min<std::size_t>(30000, big.size() - off)));
    }
    std::string resp;
    boost::system::error_code ec;
    asio::read(s, asio::dynamic_buffer(resp), ec);
    CHECK(Has(resp, "202") && last_body == big, "POST with a 200 KB body arrives complete");
  }
  {
    asio::io_context cio;
    tcp::socket s(cio);
    s.connect({asio::ip::make_address("127.0.0.1"), port});
    const std::string req = "POST /api/token HTTP/1.1\r\n" + host +
        "X-Requested-With: fptn\r\nContent-Length: 99999999\r\n\r\n";
    asio::write(s, asio::buffer(req));
    std::string resp;
    boost::system::error_code ec;
    asio::read(s, asio::dynamic_buffer(resp), ec);
    CHECK(Has(resp, "413"), "absurd Content-Length is refused");
  }
  d.Stop();
  ioc.stop();
  io.join();

  std::printf("\n%s\n", g_fail ? "FAILED" : "ALL PASSED");
  return g_fail ? 1 : 0;
}
