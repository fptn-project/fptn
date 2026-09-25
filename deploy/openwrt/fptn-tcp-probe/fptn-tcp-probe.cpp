/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <argparse/argparse.hpp>

namespace {

std::uint64_t NowMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

}  // namespace

int main(int argc, char** argv) {
  argparse::ArgumentParser args("fptn-tcp-probe");
  args.add_argument("host").help("server IPv4 address");
  args.add_argument("port").help("server TCP port").scan<'i', int>();
  args.add_argument("--timeout-ms")
      .help("connect timeout in milliseconds")
      .default_value(3000)
      .scan<'i', int>();
  args.add_argument("--interface")
      .help("bind the probe socket to this network device")
      .default_value(std::string{});

  try {
    args.parse_args(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "%s\n", e.what());
    return EXIT_FAILURE;
  }

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<unsigned short>(args.get<int>("port")));
  if (inet_pton(AF_INET, args.get<std::string>("host").c_str(),
          &addr.sin_addr) != 1) {
    return EXIT_FAILURE;
  }

  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    return EXIT_FAILURE;
  }

  const std::string iface = args.get<std::string>("--interface");
  if (!iface.empty()) {
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.size());
  }

  const auto start = NowMs();
  int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (rc != 0 && errno == EINPROGRESS) {
    const int timeout_ms = args.get<int>("--timeout-ms");
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(fd + 1, nullptr, &wset, nullptr, &tv) <= 0) {
      close(fd);
      return EXIT_FAILURE;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    rc = err;
  }

  const long elapsed = NowMs() - start;
  close(fd);
  if (rc != 0) {
    return EXIT_FAILURE;
  }
  std::printf("%ld\n", elapsed);
  return EXIT_SUCCESS;
}
