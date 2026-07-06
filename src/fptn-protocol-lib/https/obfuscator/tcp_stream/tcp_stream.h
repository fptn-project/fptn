/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

template <typename Stream>
class TcpStream {
 public:
  using executor_type = typename Stream::executor_type;
  using next_layer_type = Stream;
  using lowest_layer_type = Stream;

  explicit TcpStream(executor_type ex)
      : stream_(ex), strand_(ex), obfuscator_(nullptr) {}

  explicit TcpStream(executor_type ex, IObfuscatorSPtr obfuscator = nullptr)
      : stream_(ex), strand_(ex), obfuscator_(std::move(obfuscator)) {}

  explicit TcpStream(Stream&& stream, IObfuscatorSPtr obfuscator = nullptr)
      : stream_(std::move(stream)),
        strand_(stream_.get_executor()),
        obfuscator_(std::move(obfuscator)) {}

  TcpStream(const TcpStream&) = delete;
  TcpStream& operator=(const TcpStream&) = delete;

  TcpStream(TcpStream&& other) noexcept
      : stream_(std::move(other.stream_)),
        strand_(std::move(other.strand_)),
        obfuscator_(std::move(other.obfuscator_)) {}

  TcpStream& operator=(TcpStream&& other) noexcept {
    if (this != &other) {
      stream_ = std::move(other.stream_);
      strand_ = std::move(other.strand_);
      obfuscator_ = std::move(other.obfuscator_);
    }
    return *this;
  }

  executor_type get_executor() { return stream_.get_executor(); }

  next_layer_type& next_layer() { return stream_; }

  const next_layer_type& next_layer() const { return stream_; }

  lowest_layer_type& lowest_layer() { return stream_; }

  const lowest_layer_type& lowest_layer() const { return stream_; }

  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    if (!obfuscator_) {
      return stream_.read_some(buffers, ec);
    }

    constexpr std::size_t kTempBufferSize = 16 * 1024;
    std::array<std::uint8_t, kTempBufferSize> temp_buffer;

    while (true) {
      if (obfuscator_->HasPendingData()) {
        auto deobfuscated = obfuscator_->Deobfuscate();
        if (deobfuscated.has_value()) {
          return boost::asio::buffer_copy(buffers,
              boost::asio::buffer(deobfuscated->data(), deobfuscated->size()));
        }
      }

      const std::size_t bytes_read =
          stream_.read_some(boost::asio::buffer(temp_buffer), ec);

      if (ec) {
        return bytes_read;
      }

      if (bytes_read == 0) {
        return 0;
      }

      obfuscator_->AddData(temp_buffer.data(), bytes_read);

      auto deobfuscated = obfuscator_->Deobfuscate();
      if (deobfuscated.has_value()) {
        return boost::asio::buffer_copy(buffers,
            boost::asio::buffer(deobfuscated->data(), deobfuscated->size()));
      }
    }
  }

  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    if (!obfuscator_) {
      boost::asio::dispatch(
          strand_, [this, buffers,
                       handler = std::forward<ReadHandler>(handler)]() mutable {
            stream_.async_read_some(buffers, std::move(handler));
          });
      return;
    }

    boost::asio::dispatch(strand_, [this, buffers,
                                       handler = std::forward<ReadHandler>(
                                           handler)]() mutable {
      if (obfuscator_->HasPendingData()) {
        auto deobfuscated = obfuscator_->Deobfuscate();
        if (deobfuscated.has_value()) {
          const std::size_t bytes_copied = boost::asio::buffer_copy(
              buffers, boost::asio::buffer(deobfuscated.value()));
          handler(boost::system::error_code{}, bytes_copied);
          return;
        }
      }
      stream_.async_read_some(buffers,
          [this, buffers, handler = std::move(handler)](
              boost::system::error_code ec, std::size_t bytes_read) mutable {
            if (ec || bytes_read == 0) {
              handler(ec, bytes_read);
              return;
            }

            if (has_single_buffer(buffers)) {
              const auto& it = boost::asio::buffer_sequence_begin(buffers);
              const boost::asio::mutable_buffer& first_buffer = *it;
              const std::uint8_t* data_ptr =
                  static_cast<std::uint8_t*>(first_buffer.data());

              obfuscator_->AddData(data_ptr, bytes_read);

              auto deobfuscated = obfuscator_->Deobfuscate();

              if (deobfuscated.has_value()) {
                const std::size_t bytes_copied = boost::asio::buffer_copy(
                    buffers, boost::asio::buffer(deobfuscated.value()));
                handler(ec, bytes_copied);
              } else {
                this->async_read_some(buffers, std::move(handler));
              }
            } else {
              std::vector<std::uint8_t> temp_data(bytes_read);
              boost::asio::buffer_copy(boost::asio::buffer(temp_data), buffers);
              obfuscator_->AddData(temp_data.data(), bytes_read);

              auto deobfuscated = obfuscator_->Deobfuscate();

              if (deobfuscated.has_value()) {
                const std::size_t bytes_copied = boost::asio::buffer_copy(
                    buffers, boost::asio::buffer(deobfuscated.value()));
                handler(ec, bytes_copied);
              } else {
                boost::asio::dispatch(strand_,
                    [this, buffers,
                        handler =
                            std::forward<ReadHandler>(handler)]() mutable {
                      this->async_read_some(buffers, std::move(handler));
                    });
              }
            }
          });
    });
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    if (!obfuscator_) {
      return stream_.write_some(buffers, ec);
    }

    const std::size_t plain_size = boost::asio::buffer_size(buffers);
    std::vector<std::uint8_t> plain_data(plain_size);
    boost::asio::buffer_copy(boost::asio::buffer(plain_data), buffers);

    auto obfuscated =
        obfuscator_->Obfuscate(plain_data.data(), plain_data.size());

    if (!obfuscated.has_value()) {
      ec = boost::asio::error::eof;
      return 0;
    }

    boost::asio::write(stream_, boost::asio::buffer(obfuscated.value()), ec);
    if (ec) {
      return 0;
    }
    return plain_size;
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    if (!obfuscator_) {
      boost::asio::dispatch(strand_,
          [this, buffers,
              handler = std::forward<WriteHandler>(handler)]() mutable {
            stream_.async_write_some(buffers, std::move(handler));
          });
      return;
    }

    const std::size_t total_size = boost::asio::buffer_size(buffers);
    auto plain_data = std::make_shared<std::vector<std::uint8_t>>(total_size);
    boost::asio::buffer_copy(boost::asio::buffer(*plain_data), buffers);

    boost::asio::dispatch(
        strand_, [this, plain_data,
                     handler = std::forward<WriteHandler>(handler)]() mutable {
          auto obfuscated_data =
              obfuscator_->Obfuscate(plain_data->data(), plain_data->size());
          if (!obfuscated_data.has_value()) {
            handler(boost::system::error_code(boost::asio::error::eof), 0);
            return;
          }

          const std::size_t plain_size = plain_data->size();
          auto record = std::make_shared<std::vector<std::uint8_t>>(
              std::move(obfuscated_data.value()));
          boost::asio::async_write(stream_, boost::asio::buffer(*record),
              [record, plain_size, handler = std::move(handler)](
                  boost::system::error_code ec, std::size_t) mutable {
                handler(ec, ec ? 0 : plain_size);
              });
        });
  }

  template <typename... Args>
  auto async_connect(Args&&... args) {
    return stream_.async_connect(std::forward<Args>(args)...);
  }

  void close() { stream_.close(); }

  void close(boost::system::error_code& ec) { stream_.close(ec); }

  template <typename Option>
  void set_option(const Option& option) {
    stream_.set_option(option);
  }

  void expires_after(std::chrono::steady_clock::duration expiry_time) {
    stream_.expires_after(expiry_time);
  }

  void expires_never() { stream_.expires_never(); }

  bool is_open() const { return stream_.is_open(); }

  auto remote_endpoint() { return stream_.socket().remote_endpoint(); }

  auto remote_endpoint(boost::system::error_code& ec) {
    return stream_.socket().remote_endpoint(ec);
  }

  auto local_endpoint() { return stream_.socket().local_endpoint(); }

  auto local_endpoint(boost::system::error_code& ec) {
    return stream_.socket().local_endpoint(ec);
  }

  void set_obfuscator(IObfuscatorSPtr obfuscator) {
    obfuscator_ = std::move(obfuscator);
  }

  IObfuscatorSPtr get_obfuscator() const { return obfuscator_; }

 protected:
  template <typename Sequence>
  static bool has_single_buffer(const Sequence& buffers) {
    std::size_t count = 0;
    auto end = boost::asio::buffer_sequence_end(buffers);
    for (auto it = boost::asio::buffer_sequence_begin(buffers); it != end;
        ++it) {
      ++count;
    }
    return count == 1;
  }

 private:
  Stream stream_;
  boost::asio::strand<executor_type> strand_;
  IObfuscatorSPtr obfuscator_;
};

}  // namespace fptn::protocol::https::obfuscator

namespace boost::beast {

template <typename AsyncStream>
inline void teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    boost::system::error_code& ec) {
  teardown(role, stream.next_layer(), ec);
}

template <typename AsyncStream, typename TeardownHandler>
inline void async_teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    TeardownHandler&& handler) {
  async_teardown(
      role, stream.next_layer(), std::forward<TeardownHandler>(handler));
}

}  // namespace boost::beast
