/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"

namespace fptn::protocol::https {

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  using OnConnectedCallback = std::function<void()>;

  explicit WebsocketClient(fptn::common::network::IPv4Address server_ip,
      int server_port,
      fptn::common::network::IPv4Address tun_interface_address_ipv4,
      fptn::common::network::IPv6Address tun_interface_address_ipv6,
      NewIPPacketCallback new_ip_pkt_callback,
      std::string sni,
      std::string access_token,
      std::string expected_md5_fingerprint,
      CensorshipStrategy censorship_strategy,
      OnConnectedCallback on_connected_callback = nullptr,
      int thread_number = 4);

  virtual ~WebsocketClient();

  WebsocketClient(const WebsocketClient&) = delete;
  WebsocketClient& operator=(const WebsocketClient&) = delete;
  WebsocketClient(WebsocketClient&&) = delete;
  WebsocketClient& operator=(WebsocketClient&&) = delete;

  void Run();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted() const;

 protected:
  boost::asio::awaitable<bool> RunInternal();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  boost::asio::awaitable<bool> Connect();

  boost::asio::awaitable<bool> PerformFakeHandshake2();

  void StartWatchdog();

  std::vector<std::uint8_t> GenerateHandshakePacket() const;

 private:
  const std::string kUrlWebSocket_ = "/fptn";
  const std::size_t kMaxSizeOutQueue_ = 1024;

  mutable std::mutex mutex_;
  std::atomic<bool> running_{false};
  std::atomic<bool> was_stopped_{false};
  std::atomic<bool> was_inited_{false};
  std::atomic<bool> was_connected_{false};

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  const CensorshipStrategy censorship_strategy_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;

  websocket_type ws_;

  boost::asio::strand<boost::asio::io_context::executor_type> strand_;

  boost::asio::steady_timer watchdog_timer_;

  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;

  const fptn::common::network::IPv4Address server_ip_;
  const std::string server_port_str_;

  const fptn::common::network::IPv4Address tun_interface_address_ipv4_;
  const fptn::common::network::IPv6Address tun_interface_address_ipv6_;

  NewIPPacketCallback new_ip_pkt_callback_;

  const std::string sni_;
  const std::string access_token_;
  const std::string expected_md5_fingerprint_;

  OnConnectedCallback on_connected_callback_;

  boost::asio::cancellation_signal cancel_signal_;

  obfuscator::IObfuscatorSPtr obfuscator_;
};

using WebsocketClientSPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
