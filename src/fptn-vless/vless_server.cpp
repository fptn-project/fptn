#include "fptn-vless/vless_server.h"

#include <cstdio>
#include <deque>
#include <random>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-vless/events.h"

namespace asio = boost::asio;
using asio::ip::tcp;

namespace fptn::vless {

bool ParseUuid(const std::string& text, Uuid& out) {
  std::string hex;
  for (const char c : text) {
    if (c != '-') {
      hex.push_back(c);
    }
  }
  if (hex.size() != 32) {
    return false;
  }
  for (std::size_t i = 0; i < 16; ++i) {
    unsigned value = 0;
    if (std::sscanf(hex.c_str() + i * 2, "%2x", &value) != 1) {  // NOLINT
      return false;
    }
    out[i] = static_cast<std::uint8_t>(value);
  }
  return true;
}

std::string UuidToString(const Uuid& u) {
  char buf[40];
  std::snprintf(buf, sizeof(buf),  // NOLINT
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11],
      u[12], u[13], u[14], u[15]);
  return buf;
}

Uuid GenerateUuid() {
  std::random_device rd;
  Uuid u{};
  for (auto& b : u) {
    b = static_cast<std::uint8_t>(rd());
  }
  u[6] = (u[6] & 0x0F) | 0x40;  // version 4
  u[8] = (u[8] & 0x3F) | 0x80;
  return u;
}

class VlessSession : public std::enable_shared_from_this<VlessSession> {
 public:
  VlessSession(asio::io_context& ioc, tcp::socket socket,
      const VlessServer::Config& config, UserspaceStack& stack)
      : ioc_(ioc),
        socket_(std::move(socket)),
        config_(config),
        stack_(stack),
        timer_(ioc) {}

  ~VlessSession() {
    if (flow_) {
      flow_->Close(true);
    }
  }

  // The session owns itself until Finish(): otherwise nothing would keep it
  // alive while we wait for the upstream connect or after a client half-close.
  void Start() {
    keepalive_ = shared_from_this();
    ReadFixedHeader();
  }

 private:
  struct Chunk {
    Bytes data;
    std::function<void()> consumed;
  };

  /* ---------------------------- header ---------------------------- */

  void ReadFixedHeader() {
    asio::async_read(socket_, asio::buffer(head_, 18),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t) {
          if (ec) {
            return self->Finish(true);
          }
          if (self->head_[0] != 0 ||
              !std::equal(self->head_ + 1, self->head_ + 17,
                  self->config_.uuid.begin())) {
            SPDLOG_WARN("vless: bad version or uuid from {}",
                self->RemoteName());
            return self->Finish(true);
          }
          self->ReadAddons(self->head_[17]);
        });
  }

  void ReadAddons(std::size_t len) {
    addons_.resize(len);
    if (len == 0) {
      return ReadCommand();
    }
    asio::async_read(socket_, asio::buffer(addons_),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t) {
          if (ec) {
            return self->Finish(true);
          }
          self->ReadCommand();
        });
  }

  void ReadCommand() {
    asio::async_read(socket_, asio::buffer(cmd_, 4),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t) {
          if (ec) {
            return self->Finish(true);
          }
          const std::uint8_t cmd = self->cmd_[0];
          self->target_.port = static_cast<std::uint16_t>(
              (self->cmd_[1] << 8) | self->cmd_[2]);
          const std::uint8_t atype = self->cmd_[3];
          if (cmd != 1) {
            SPDLOG_WARN("vless: unsupported command {} (only TCP)", cmd);
            return self->Finish(true);
          }
          self->ReadAddress(atype);
        });
  }

  void ReadAddress(std::uint8_t atype) {
    if (atype == 1) {
      asio::async_read(socket_, asio::buffer(addr_, 4),
          [self = shared_from_this()](const boost::system::error_code& ec,
              std::size_t) {
            if (ec) {
              return self->Finish(true);
            }
            self->target_.is_ipv4 = true;
            std::copy(self->addr_, self->addr_ + 4,
                reinterpret_cast<std::uint8_t*>(&self->target_.ipv4_be));
            self->ConnectUpstream();
          });
    } else if (atype == 2) {
      asio::async_read(socket_, asio::buffer(addr_, 1),
          [self = shared_from_this()](const boost::system::error_code& ec,
              std::size_t) {
            if (ec || self->addr_[0] == 0) {
              return self->Finish(true);
            }
            self->host_.resize(self->addr_[0]);
            asio::async_read(self->socket_, asio::buffer(self->host_),
                [self](const boost::system::error_code& ec2, std::size_t) {
                  if (ec2) {
                    return self->Finish(true);
                  }
                  self->target_.is_ipv4 = false;
                  self->target_.host = self->host_;
                  self->ConnectUpstream();
                });
          });
    } else {
      SPDLOG_WARN("vless: unsupported address type {} (IPv6?)", atype);
      Finish(true);
    }
  }

  /* --------------------------- upstream --------------------------- */

  void ConnectUpstream() {
    std::weak_ptr<VlessSession> weak = weak_from_this();
    asio::io_context* ioc = &ioc_;  // do not capture `this`: lwIP callbacks may outlive the session
    auto post = [ioc, weak](auto fn) {
      asio::post(*ioc, [weak, fn = std::move(fn)]() mutable {
        if (auto s = weak.lock()) {
          fn(*s);
        }
      });
    };

    FlowCallbacks cb;
    cb.on_connected = [post](bool ok) {
      post([ok](VlessSession& s) { s.OnUpstreamConnected(ok); });
    };
    cb.on_data = [post](Bytes data, std::function<void()> consumed) {
      post([d = std::move(data), c = std::move(consumed)](
               VlessSession& s) mutable {
        s.down_q_.push_back({std::move(d), std::move(c)});
        s.PumpDown();
      });
    };
    cb.on_eof = [post]() {
      post([](VlessSession& s) {
        s.remote_eof_ = true;
        s.PumpDown();
      });
    };
    cb.on_error = [post]() {
      post([](VlessSession& s) {
        s.flow_.reset();  // already dead
        s.Finish(true);
      });
    };

    timer_.expires_after(std::chrono::seconds(config_.connect_timeout_sec));
    timer_.async_wait([weak](const boost::system::error_code& ec) {
      if (!ec) {
        if (auto s = weak.lock()) {
          SPDLOG_WARN("vless: upstream connect timeout");
          s->Finish(true);
        }
      }
    });
    flow_ = stack_.Connect(target_, std::move(cb));
  }

  void OnUpstreamConnected(bool ok) {
    timer_.cancel();
    if (!ok) {
      flow_.reset();
      SPDLOG_WARN("vless: upstream connect failed");
      return Finish(true);
    }
    static const std::uint8_t kResponse[2] = {0, 0};
    asio::async_write(socket_, asio::buffer(kResponse),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t) {
          if (ec) {
            return self->Finish(true);
          }
          self->header_sent_ = true;
          self->PumpUp();
          self->PumpDown();
        });
  }

  /* ----------------------------- relay ----------------------------- */

  // client socket -> tunnel
  void PumpUp() {
    socket_.async_read_some(asio::buffer(up_buf_),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t n) {
          if (!self->flow_) {
            return;
          }
          if (ec) {
            if (ec == asio::error::eof) {
              self->client_eof_ = true;
              self->flow_->ShutdownWrite();
              self->MaybeFinish();
            } else {
              self->Finish(true);
            }
            return;
          }
          std::weak_ptr<VlessSession> weak = self->weak_from_this();
          asio::io_context& ioc = self->ioc_;
          self->flow_->Write(
              Bytes(self->up_buf_.begin(), self->up_buf_.begin() + n),
              [weak, &ioc]() {  // stack thread
                asio::post(ioc, [weak]() {
                  if (auto s = weak.lock()) {
                    s->PumpUp();
                  }
                });
              });
        });
  }

  // tunnel -> client socket (ordered, one write in flight)
  void PumpDown() {
    if (!header_sent_ || writing_ || finished_) {
      return;
    }
    if (down_q_.empty()) {
      if (remote_eof_ && !remote_done_) {
        remote_done_ = true;
        boost::system::error_code ignored;
        socket_.shutdown(tcp::socket::shutdown_send, ignored);
        timer_.expires_after(
            std::chrono::seconds(config_.linger_after_remote_close_sec));
        timer_.async_wait([weak = weak_from_this()](
                              const boost::system::error_code& ec) {
          if (!ec) {
            if (auto s = weak.lock()) {
              s->Finish(false);
            }
          }
        });
        MaybeFinish();
      }
      return;
    }
    writing_ = true;
    current_ = std::move(down_q_.front());
    down_q_.pop_front();
    asio::async_write(socket_, asio::buffer(current_.data),
        [self = shared_from_this()](const boost::system::error_code& ec,
            std::size_t) {
          self->writing_ = false;
          if (ec) {
            return self->Finish(true);
          }
          if (self->current_.consumed) {
            self->current_.consumed();  // reopen the TCP receive window
          }
          self->PumpDown();
        });
  }

  void MaybeFinish() {
    if (client_eof_ && remote_done_) {
      Finish(false);
    }
  }

  void Finish(bool abort) {
    if (finished_) {
      return;
    }
    finished_ = true;
    timer_.cancel();
    boost::system::error_code ignored;
    socket_.close(ignored);
    if (flow_) {
      flow_->Close(abort);
      flow_.reset();
    }
    keepalive_.reset();  // must stay the last statement: may destroy `this`
  }

  std::string RemoteName() {
    boost::system::error_code ec;
    const auto ep = socket_.remote_endpoint(ec);
    return ec ? std::string("?") : ep.address().to_string();
  }

  asio::io_context& ioc_;
  tcp::socket socket_;
  const VlessServer::Config config_;
  UserspaceStack& stack_;
  asio::steady_timer timer_;

  std::uint8_t head_[18]{};
  Bytes addons_;
  std::uint8_t cmd_[4]{};
  std::uint8_t addr_[4]{};
  std::string host_;
  Target target_;

  std::shared_ptr<VlessSession> keepalive_;
  TcpFlowPtr flow_;
  std::array<std::uint8_t, 32 * 1024> up_buf_{};
  std::deque<Chunk> down_q_;
  Chunk current_;
  bool header_sent_ = false;
  bool writing_ = false;
  bool remote_eof_ = false;
  bool remote_done_ = false;
  bool client_eof_ = false;
  bool finished_ = false;
};

VlessServer::VlessServer(
    asio::io_context& ioc, Config config, UserspaceStack& stack)
    : ioc_(ioc), config_(std::move(config)), stack_(stack), acceptor_(ioc) {}

bool VlessServer::Start() {
  boost::system::error_code ec;
  const auto addr = asio::ip::make_address(config_.listen_address, ec);
  if (ec) {
    SPDLOG_ERROR("vless: bad listen address '{}'", config_.listen_address);
    return false;
  }
  const tcp::endpoint ep(addr, config_.port);
  acceptor_.open(ep.protocol(), ec);
  acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
  acceptor_.bind(ep, ec);
  if (ec) {
    SPDLOG_ERROR("vless: cannot bind {}:{} ({})", config_.listen_address,
        config_.port, ec.message());
    return false;
  }
  acceptor_.listen(asio::socket_base::max_listen_connections, ec);
  if (ec) {
    return false;
  }
  DoAccept();
  return true;
}

void VlessServer::Stop() {
  boost::system::error_code ignored;
  acceptor_.close(ignored);
}

void VlessServer::DoAccept() {
  acceptor_.async_accept(
      [this](const boost::system::error_code& ec, tcp::socket socket) {
        if (ec == asio::error::operation_aborted) {
          return;
        }
        if (!ec) {
          boost::system::error_code ignored;
          socket.set_option(tcp::no_delay(true), ignored);
          {
            const auto peer = socket.remote_endpoint(ignored);
            if (!ignored &&
                seen_clients_.insert(peer.address().to_string()).second) {
              Notify("New VLESS client connected from {}",
                  peer.address().to_string());
            }
          }
          std::make_shared<VlessSession>(ioc_, std::move(socket), config_,
              stack_)
              ->Start();
        }
        DoAccept();
      });
}

}  // namespace fptn::vless
