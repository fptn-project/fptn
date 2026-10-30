#pragma once

/*
 * Minimal VLESS inbound (plain TCP, no TLS, no flow): accepts VLESS clients
 * from the LAN and relays each TCP request through the userspace stack.
 *
 * Supported: command TCP (0x01), address types IPv4 / domain.
 * Not supported (connection is closed): UDP, Mux, IPv6 targets.
 *
 * Request header:
 *   1B version(0) | 16B uuid | 1B addons_len | addons | 1B cmd | 2B port |
 *   1B addr_type(1=IPv4,2=domain,3=IPv6) | addr
 * Response header: 1B version(0) | 1B addons_len(0)
 */

#include <array>
#include <cstdint>
#include <memory>

#include <string>
#include <unordered_set>

#include <boost/asio.hpp>

#include "fptn-vless/userspace_stack.h"

namespace fptn::vless {

using Uuid = std::array<std::uint8_t, 16>;

bool ParseUuid(const std::string& text, Uuid& out);
std::string UuidToString(const Uuid& uuid);
Uuid GenerateUuid();

class VlessServer {
 public:
  struct Config {
    std::string listen_address = "0.0.0.0";
    std::uint16_t port = 10800;
    Uuid uuid{};
    int connect_timeout_sec = 15;
    int linger_after_remote_close_sec = 10;
  };

  VlessServer(boost::asio::io_context& ioc, Config config,
      UserspaceStack& stack);

  bool Start();  // false if the port cannot be bound
  void Stop();

 private:
  friend class VlessSession;
  void DoAccept();

  boost::asio::io_context& ioc_;
  Config config_;
  UserspaceStack& stack_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::unordered_set<std::string> seen_clients_;  // accept handler only
};

}  // namespace fptn::vless
