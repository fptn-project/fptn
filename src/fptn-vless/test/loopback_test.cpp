// End-to-end test: VLESS client -> VlessServer -> UserspaceStack(lwIP) -> framed
// IP packets over pipes -> echo_peer (second lwIP) and back. No fptn deps.
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include "fptn-vless/tunnel_check.h"
#include "fptn-vless/userspace_stack.h"
#include "fptn-vless/vless_server.h"

using namespace fptn::vless;
namespace asio = boost::asio;
using asio::ip::tcp;

static int g_fail = 0;
#define CHECK(cond, msg)                                              \
  do {                                                                \
    if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fail; }       \
    else { std::printf("  ok:   %s\n", msg); }                         \
  } while (0)

static bool ReadFull(int fd, void* d, size_t n) {
  char* p = static_cast<char*>(d);
  while (n) { ssize_t r = read(fd, p, n); if (r <= 0) return false; p += r; n -= (size_t)r; }
  return true;
}

static Uuid g_uuid;
static uint16_t g_port = 18800;

static std::vector<uint8_t> Header(const Uuid& u, uint8_t atype, const std::vector<uint8_t>& addr, uint16_t port) {
  std::vector<uint8_t> h{0};
  h.insert(h.end(), u.begin(), u.end());
  h.push_back(0);        // addons len
  h.push_back(1);        // cmd TCP
  h.push_back((uint8_t)(port >> 8)); h.push_back((uint8_t)port);
  h.push_back(atype);
  h.insert(h.end(), addr.begin(), addr.end());
  return h;
}

static tcp::socket Dial(asio::io_context& ioc) {
  tcp::socket s(ioc);
  s.connect({asio::ip::make_address("127.0.0.1"), g_port});
  return s;
}
static std::vector<uint8_t> To10_0_0_2() { return {10, 0, 0, 2}; }

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  signal(SIGPIPE, SIG_IGN);
  g_uuid = GenerateUuid();

  int to_peer[2], from_peer[2];
  if (pipe(to_peer) || pipe(from_peer)) return 2;
  pid_t pid = fork();
  if (pid == 0) {
    dup2(to_peer[0], 0); dup2(from_peer[1], 1);
    close(to_peer[1]); close(from_peer[0]);
    execl("./echo_peer", "echo_peer", (char*)nullptr);
    _exit(127);
  }
  close(to_peer[0]); close(from_peer[1]);

  auto& stack = UserspaceStack::Instance();
  UserspaceStack::Config sc; sc.ipv4 = "10.0.0.1"; sc.mtu = 1420;
  if (!stack.Start(sc)) { std::puts("stack start failed"); return 2; }

  std::atomic<bool> run{true};
  std::thread tx([&] {  // stack -> peer
    std::vector<uint8_t> buf(65536);
    while (run) {
      int n = stack.TakeOutput(buf.data(), buf.size(), 5);
      if (n <= 0) continue;
      uint8_t hdr[2] = {(uint8_t)(n >> 8), (uint8_t)n};
      if (write(to_peer[1], hdr, 2) != 2 || write(to_peer[1], buf.data(), (size_t)n) != n) break;
    }
  });
  std::thread rx([&] {  // peer -> stack
    std::vector<uint8_t> buf(65536);
    for (;;) {
      uint8_t hdr[2];
      if (!ReadFull(from_peer[0], hdr, 2)) break;
      size_t n = ((size_t)hdr[0] << 8) | hdr[1];
      if (!ReadFull(from_peer[0], buf.data(), n)) break;
      stack.Input(buf.data(), n);
    }
  });

  asio::io_context ioc;
  VlessServer::Config vc; vc.listen_address = "127.0.0.1"; vc.port = g_port; vc.uuid = g_uuid;
  vc.connect_timeout_sec = 3; vc.linger_after_remote_close_sec = 2;
  VlessServer server(ioc, vc, stack);
  if (!server.Start()) { std::puts("server start failed"); return 2; }
  auto guard = asio::make_work_guard(ioc);
  std::thread io([&] { ioc.run(); });

  asio::io_context cio;
  boost::system::error_code ec;

  std::puts("[1] echo through the tunnel");
  {
    auto s = Dial(cio);
    auto h = Header(g_uuid, 1, To10_0_0_2(), 7);
    h.insert(h.end(), {'h', 'e', 'l', 'l', 'o'});
    asio::write(s, asio::buffer(h));
    uint8_t resp[7]; asio::read(s, asio::buffer(resp), ec);
    CHECK(!ec && resp[0] == 0 && resp[1] == 0, "VLESS response header 00 00");
    CHECK(!ec && std::memcmp(resp + 2, "hello", 5) == 0, "payload echoed back");
  }

  std::puts("[2] download 4 MiB (lwIP -> socket, backpressure)");
  {
    auto t0 = std::chrono::steady_clock::now();
    auto s = Dial(cio);
    asio::write(s, asio::buffer(Header(g_uuid, 1, To10_0_0_2(), 9)));
    uint8_t resp[2]; asio::read(s, asio::buffer(resp));
    size_t total = 0; bool pattern_ok = true; uint8_t buf[65536];
    for (;;) {
      size_t n = s.read_some(asio::buffer(buf), ec);
      for (size_t i = 0; i < n; ++i) if (buf[i] != (uint8_t)((total + i) % 251)) pattern_ok = false;
      total += n;
      if (ec) break;
    }
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(total == 4u * 1024 * 1024, "received exactly 4 MiB");
    CHECK(pattern_ok, "byte pattern intact");
    std::printf("        %.2f s, %.1f MiB/s\n", sec, 4.0 / sec);
  }

  std::puts("[3] upload 4 MiB (socket -> lwIP) + half-close");
  {
    auto t0 = std::chrono::steady_clock::now();
    auto s = Dial(cio);
    auto h = Header(g_uuid, 1, To10_0_0_2(), 19);
    asio::write(s, asio::buffer(h));
    std::vector<uint8_t> chunk(32768); uint32_t sum = 0; size_t sent = 0;
    const size_t N = 4u * 1024 * 1024;
    while (sent < N) {
      for (size_t i = 0; i < chunk.size(); ++i) { chunk[i] = (uint8_t)((sent + i) % 251); sum += chunk[i]; }
      asio::write(s, asio::buffer(chunk));
      sent += chunk.size();
    }
    s.shutdown(tcp::socket::shutdown_send);
    uint8_t resp[2 + 8]; asio::read(s, asio::buffer(resp), ec);
    uint32_t cnt = (uint32_t)resp[2] << 24 | resp[3] << 16 | resp[4] << 8 | resp[5];
    uint32_t sm = (uint32_t)resp[6] << 24 | resp[7] << 16 | resp[8] << 8 | resp[9];
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(!ec, "peer answered after FIN");
    CHECK(cnt == N, "peer counted 4 MiB");
    CHECK(sm == sum, "peer checksum matches");
    std::printf("        %.2f s, %.1f MiB/s\n", sec, 4.0 / sec);
  }

  std::puts("[4] 8 parallel downloads");
  {
    std::atomic<int> good{0};
    std::vector<std::thread> th;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 8; ++i) th.emplace_back([&] {
      asio::io_context c2; tcp::socket s(c2); boost::system::error_code e;
      s.connect({asio::ip::make_address("127.0.0.1"), g_port});
      asio::write(s, asio::buffer(Header(g_uuid, 1, To10_0_0_2(), 9)));
      size_t total = 0; uint8_t buf[65536];
      for (;;) { size_t n = s.read_some(asio::buffer(buf), e); total += n; if (e) break; }
      if (total == 2 + 4u * 1024 * 1024) ++good;
    });
    for (auto& t : th) t.join();
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(good == 8, "all 8 downloads complete with the right size");
    std::printf("        %.2f s total (%.1f MiB/s aggregate)\n", sec, 32.0 / sec);
  }

  std::puts("[5] error handling");
  {
    Uuid bad = g_uuid; bad[0] ^= 0xFF;
    auto s = Dial(cio);
    asio::write(s, asio::buffer(Header(bad, 1, To10_0_0_2(), 7)));
    uint8_t b[1]; s.read_some(asio::buffer(b), ec);
    CHECK(ec == asio::error::eof || ec == asio::error::connection_reset, "wrong UUID -> connection closed");
  }
  {
    auto t0 = std::chrono::steady_clock::now();
    auto s = Dial(cio);
    asio::write(s, asio::buffer(Header(g_uuid, 1, {10, 0, 0, 99}, 80)));
    uint8_t b[1]; s.read_some(asio::buffer(b), ec);
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ec && sec > 2.0 && sec < 6.0, "unreachable target -> closed by connect timeout (~3 s)");
  }
  {
    auto s = Dial(cio);
    auto h = Header(g_uuid, 1, To10_0_0_2(), 4444);  // closed port -> RST
    asio::write(s, asio::buffer(h));
    uint8_t b[1]; s.read_some(asio::buffer(b), ec);
    CHECK(ec, "closed remote port -> connection closed");
  }

  std::puts("[6] tunnel replaced by one to another server (failover)");
  {
    auto s = Dial(cio);
    auto h = Header(g_uuid, 1, To10_0_0_2(), 7);
    h.insert(h.end(), {'a', 'b'});
    asio::write(s, asio::buffer(h));
    uint8_t resp[4];
    asio::read(s, asio::buffer(resp), ec);
    CHECK(!ec && std::memcmp(resp + 2, "ab", 2) == 0, "established connection works");
    auto t0 = std::chrono::steady_clock::now();
    stack.ResetForNewTunnel("");  // what the failover does when it switches servers
    uint8_t b[1];
    s.read_some(asio::buffer(b), ec);
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ec && sec < 1.0, "open connection is dropped at once (client can reconnect)");
  }
  {
    auto s = Dial(cio);  // target that never answers: would wait for the 3 s timeout
    asio::write(s, asio::buffer(Header(g_uuid, 1, {10, 0, 0, 99}, 80)));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    auto t0 = std::chrono::steady_clock::now();
    stack.ResetForNewTunnel("");
    uint8_t b[1];
    s.read_some(asio::buffer(b), ec);
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ec && sec < 1.0, "half-open connection is dropped at once, not after the timeout");
  }
  {
    auto s = Dial(cio);
    auto h = Header(g_uuid, 1, To10_0_0_2(), 7);
    h.insert(h.end(), {'o', 'k'});
    asio::write(s, asio::buffer(h));
    uint8_t resp[4];
    asio::read(s, asio::buffer(resp), ec);
    CHECK(!ec && std::memcmp(resp + 2, "ok", 2) == 0, "new connections work after the reset");
  }

  std::puts("[7] tunnel check explains what is broken");
  {
    // The peer only owns 10.0.0.2, so 1.1.1.1 is "not answered by the server".
    auto r = CheckTunnel(stack, 2);
    CHECK(!r.by_ip_ms && !r.by_name_ms, "no answer from the server: both probes fail");
    CHECK(r.packets_out > 0, "packets were handed to the tunnel");
    TunnelCheckResult silent;  // nothing came back
    silent.packets_out = 5;
    CHECK(silent.Summary().find("does not answer") != std::string::npos,
        "summary: no packets back -> server does not answer");
    TunnelCheckResult no_dns;
    no_dns.by_ip_ms = 120;
    no_dns.packets_out = 9;
    no_dns.packets_in = 4;
    CHECK(no_dns.Summary().find("DNS") != std::string::npos,
        "summary: IP works, names do not -> DNS");
    TunnelCheckResult dead;
    CHECK(dead.Summary().find("Nothing left") != std::string::npos,
        "summary: no packets out -> stack/tunnel not working");
    TunnelCheckResult good;
    good.by_ip_ms = 100;
    good.by_name_ms = 200;
    CHECK(good.Ok() && good.Summary().find("FAILED") == std::string::npos,
        "summary: all good");
    CHECK(!TunnelCarriesTraffic(stack, 2), "TunnelCarriesTraffic() is false");
  }

  std::printf("\n%s  (stack drops in/out: %llu/%llu)\n", g_fail ? "FAILED" : "ALL PASSED",
      (unsigned long long)stack.DroppedIn(), (unsigned long long)stack.DroppedOut());

  run = false; server.Stop(); guard.reset(); ioc.stop();
  kill(pid, SIGTERM); waitpid(pid, nullptr, 0);
  close(to_peer[1]); tx.join(); io.join(); rx.join();
  stack.Stop();
  return g_fail ? 1 : 0;
}
