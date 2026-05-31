/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <openssl/bio.h>    // NOLINT(build/include_order)
#include <openssl/ssl.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#ifndef __ANDROID__
#include "common/system/command.h"
#endif

#include "fptn-protocol-lib/https/utils/change_cipher_spec.h"

namespace fptn::common::network {

#ifndef __ANDROID__
inline std::vector<std::string> GetServerIpAddresses() {
  std::vector<std::string> cmd_stdout;
  fptn::common::system::command::run(
      "ip -o addr show | awk '{print $4}' | cut -d'/' -f1", cmd_stdout);
  return cmd_stdout;
}
#endif

inline void CleanSocket(boost::asio::ip::tcp::socket& socket) {
  try {
    while (socket.available() != 0) {
      boost::system::error_code ec;
      std::array<std::uint8_t, 4096> buffer{};
      const std::size_t bytes =
          socket.read_some(boost::asio::buffer(buffer), ec);
      (void)bytes;
      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("CleanSocket error: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("CleanSocket exception: {}", e.what());
  }
}

inline bool CleanSsl(const SSL* ssl) {
  if (ssl == nullptr) {
    return false;
  }
  if (BIO* rb = SSL_get_rbio(ssl)) {
    BIO_flush(rb);
    char buf[4096] = {};
    while (BIO_pending(rb) > 0) {
      BIO_read(rb, buf, sizeof(buf));
    }
  }
  return true;
}

namespace detail {

// Inspect a ServerHello body and return true if the supported_versions
// extension (type 0x002b) advertises TLS 1.3 (0x0304).
// WHY: In TLS 1.3 the ServerHello.legacy_version field is ALWAYS 0x0303
// (required by RFC 8446 §4.1.3 for backward compatibility). You cannot
// distinguish TLS 1.2 from TLS 1.3 by reading legacy_version. The real
// indicator is the supported_versions extension.
//
// body_start = index of the first byte of the ServerHello message body
//              (immediately after the 4-byte handshake header).
// body_len   = value from the 3-byte handshake length field.
inline bool IsTls13ServerHello(const std::vector<std::uint8_t>& data,
    std::size_t body_start,
    std::uint32_t body_len) noexcept {
  // ServerHello body layout (RFC 8446 §4.1.3):
  //   legacy_version        2 bytes  (always 0x03 0x03)
  //   random               32 bytes
  //   session_id_length     1 byte
  //   session_id            0..32 bytes
  //   cipher_suite          2 bytes
  //   compression_method    1 byte
  //   extensions_length     2 bytes
  //   extensions            variable
  const std::size_t body_end = body_start + body_len;
  if (body_end > data.size() || body_len < 36) {
    return false;
  }

  std::size_t p = body_start;
  p += 2;   // skip legacy_version (always 0x03 0x03 — NOT a TLS version
            // indicator)
  p += 32;  // skip random

  if (p >= body_end) {
    return false;
  }

  const std::uint8_t sid_len = data[p++];

  // session_id + cipher_suite(2) + compression(1) + ext_length(2)
  if (p + sid_len + 5 > body_end) {
    return false;
  }
  p += sid_len;  // skip session_id
  p += 2;        // skip cipher_suite
  p += 1;        // skip compression_method

  const std::uint16_t ext_total =
      (static_cast<std::uint16_t>(data[p]) << 8) | data[p + 1];
  p += 2;

  const std::size_t ext_end = std::min(p + std::size_t(ext_total), body_end);
  while (p + 4 <= ext_end) {
    const std::uint16_t ext_type =
        (static_cast<std::uint16_t>(data[p]) << 8) | data[p + 1];
    const std::uint16_t ext_len =
        (static_cast<std::uint16_t>(data[p + 2]) << 8) | data[p + 3];
    p += 4;
    if (p + ext_len > ext_end) {
      break;
    }

    // supported_versions in ServerHello: exactly one 2-byte ProtocolVersion
    if (ext_type == 0x002b && ext_len >= 2) {
      const std::uint16_t ver =
          (static_cast<std::uint16_t>(data[p]) << 8) | data[p + 1];
      if (ver == 0x0304) {
        return true;  // TLS 1.3
      }
    }
    p += ext_len;
  }
  return false;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// IsClientHelloComplete
//
// Returns true when a complete, parseable ClientHello record is present.
// The ClientHello from camouflage-tls is always a single TLS Handshake
// record, so one or two reads are sufficient in practice.
// ---------------------------------------------------------------------------
inline bool IsClientHelloComplete(const std::vector<std::uint8_t>& data) {
  if (data.size() < 5) return false;

  std::size_t pos = 0;
  while (pos + 5 <= data.size()) {
    const std::uint8_t content_type = data[pos];
    // data[pos+1..2] = record-layer version — ignored (can be 0x03 0x01)
    const std::uint16_t record_length =
        (static_cast<std::uint16_t>(data[pos + 3]) << 8) | data[pos + 4];

    if (pos + 5 + record_length > data.size()) {
      return false;  // incomplete record: accumulate more data
    }

    if (content_type == 22) {  // Handshake
      std::size_t hpos = pos + 5;
      const std::size_t hend = hpos + record_length;

      while (hpos + 4 <= hend) {
        const std::uint8_t msg_type = data[hpos];
        const std::uint32_t msg_length =
            (static_cast<std::uint32_t>(data[hpos + 1]) << 16) |
            (static_cast<std::uint32_t>(data[hpos + 2]) << 8) | data[hpos + 3];

        if (hpos + 4 + msg_length > hend) return false;
        if (msg_type == 1) return true;  // ClientHello
        hpos += 4 + msg_length;
      }
    }
    pos += 5 + record_length;
  }
  return false;
}

// ---------------------------------------------------------------------------
// IsServerHelloComplete
//
// TLS 1.2:
//   Returns true after ServerHelloDone (msg_type = 14) is found.
//   Server flight: ServerHello + [Certificate] + [ServerKeyExchange] +
//   ServerHelloDone
//
// TLS 1.3:
//   Returns true when the buffer contains:
//     1. ServerHello           (content_type = 22, msg_type = 2)
//     2. ChangeCipherSpec      (content_type = 20) — compat shim, RFC 8446 §D.4
//     3. At least one ApplicationData (content_type = 23) — encrypted handshake
//        AND that AppData is the last complete record currently in the buffer.
//
//   IMPORTANT: "last in buffer" means the server is no longer writing.
//   Because AppData records may arrive in bursts, the caller (WaitForServer*)
//   MUST use a quiet-period strategy: keep reading until 150ms of silence
//   AFTER IsServerHelloComplete first returns true, to capture the full
//   encrypted flight (EncryptedExtensions + Certificate + CertVerify +
//   Finished).
// ---------------------------------------------------------------------------
inline bool IsServerHelloComplete(const std::vector<std::uint8_t>& data) {
  if (data.size() < 5) return false;

  std::size_t pos = 0;
  bool found_server_hello = false;
  bool is_tls13 = false;
  bool handshake_done = false;

  while (pos + 5 <= data.size()) {
    const std::uint8_t content_type = data[pos];
    const std::uint16_t record_len =
        (static_cast<std::uint16_t>(data[pos + 3]) << 8) | data[pos + 4];
    if (pos + 5 + record_len > data.size()) {
      // Incomplete record: we must not guess — wait for the full payload.
      return false;
    }

    if (content_type == 22) {  // Handshake record (plaintext)
      std::size_t hpos = pos + 5;
      const std::size_t hend = hpos + record_len;

      while (hpos + 4 <= hend) {
        const std::uint8_t msg_type = data[hpos];
        const std::uint32_t msg_len =
            (static_cast<std::uint32_t>(data[hpos + 1]) << 16) |
            (static_cast<std::uint32_t>(data[hpos + 2]) << 8) | data[hpos + 3];

        if (hpos + 4 + msg_len > hend) return false;

        if (msg_type == 2) {  // ServerHello
          found_server_hello = true;
          // Must parse supported_versions extension — legacy_version is always
          // 0x0303 in both TLS 1.2 and TLS 1.3 and cannot be used for
          // detection.
          is_tls13 = detail::IsTls13ServerHello(data, hpos + 4, msg_len);
          SPDLOG_INFO("IsServerHelloComplete: ServerHello found (TLS {})",
              is_tls13 ? "1.3" : "1.2");
        }

        // TLS 1.2: ServerHelloDone (type 14) ends the server's first flight.
        if (found_server_hello && !is_tls13 && msg_type == 14) {
          handshake_done = true;
          SPDLOG_INFO("IsServerHelloComplete: TLS 1.2 ServerHelloDone");
        }

        // NOTE: In TLS 1.3, the Finished message (type 20) is ENCRYPTED inside
        // ApplicationData records. It will NEVER appear as a plaintext
        // Handshake message here — no check needed.

        hpos += 4 + msg_len;
      }
    }

    // TLS 1.3: ApplicationData (type 23) carries the encrypted server flight:
    // EncryptedExtensions, Certificate, CertificateVerify, Finished.
    // We declare "potentially done" when this AppData record is the last
    // complete record currently in the buffer. We deliberately do NOT require
    // a preceding ChangeCipherSpec: the TLS 1.3 compatibility CCS
    // (RFC 8446 §D.4) is OPTIONAL, and servers that omit it previously left
    // handshake_done false forever -> the decoy read timed out and Reality
    // failed only for those SNIs (looked flaky/intermittent). The caller's
    // quiet-period loop still captures any further AppData records.
    if (found_server_hello && is_tls13 && content_type == 23) {
      if (pos + 5 + record_len >= data.size()) {
        handshake_done = true;
        SPDLOG_INFO(
            "IsServerHelloComplete: TLS 1.3 last AppData in buffer ({} bytes "
            "total)",
            data.size());
      }
    }

    pos += 5 + record_len;
  }

  return found_server_hello && handshake_done;
}

using TlsData = std::optional<std::vector<std::uint8_t>>;

// ---------------------------------------------------------------------------
// WaitForServerTlsHello  (synchronous, blocking)
//
// Phase 1 — read until IsServerHelloComplete returns true.
// Phase 2 — keep reading for up to kQuietMs after the last received byte.
//           Any new data resets the quiet timer. This captures TLS 1.3
//           encrypted records (Certificate, etc.) that follow the CCS and
//           arrive in a burst within a few milliseconds.
// ---------------------------------------------------------------------------
inline TlsData WaitForServerTlsHello(boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  constexpr auto kPollInterval = std::chrono::milliseconds(50);
  constexpr auto kQuietMs = std::chrono::milliseconds(150);

  std::vector<std::uint8_t> data;
  data.reserve(65536);

  const auto deadline = std::chrono::steady_clock::now() + drain_timeout;

  try {
    boost::system::error_code ec;

    bool hello_complete = false;
    std::chrono::steady_clock::time_point last_data_time;
    std::array<std::uint8_t, 1024*16> buffer{};

    while (std::chrono::steady_clock::now() < deadline) {
      if (socket.available() == 0) {
        if (hello_complete &&
            std::chrono::steady_clock::now() - last_data_time >= kQuietMs) {
          SPDLOG_INFO(
              "WaitForServerTlsHello: quiet period elapsed, done ({} bytes)",
              data.size());
          return data;
        }
        std::this_thread::sleep_for(kPollInterval);
        continue;
      }

      const std::size_t bytes =
          socket.read_some(boost::asio::buffer(buffer), ec);

      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        last_data_time = std::chrono::steady_clock::now();

        if (!hello_complete && IsServerHelloComplete(data)) {
          hello_complete = true;
          SPDLOG_INFO(
              "WaitForServerTlsHello: hello complete at {} bytes, draining...",
              data.size());
        }
      }

      if (ec == boost::asio::error::eof) {
        SPDLOG_INFO("WaitForServerTlsHello: EOF, {} bytes", data.size());
        break;
      }
      if (ec) {
        SPDLOG_ERROR("WaitForServerTlsHello: {}", ec.message());
        break;
      }
    }

    if (!hello_complete) {
      SPDLOG_WARN(
          "WaitForServerTlsHello: timeout without complete ServerHello, {} "
          "bytes",
          data.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("WaitForServerTlsHello exception: {}", e.what());
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// WaitForServerTlsHelloAsync  (asynchronous coroutine)
//
// Same strategy as WaitForServerTlsHello but uses co_await instead of sleep.
// ---------------------------------------------------------------------------
inline boost::asio::awaitable<TlsData> WaitForServerTlsHelloAsync(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  constexpr auto kPollInterval = std::chrono::milliseconds(50);
  constexpr auto kQuietMs = std::chrono::milliseconds(150);

  std::vector<std::uint8_t> data;
  data.reserve(65536);

  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};

    const auto deadline = std::chrono::steady_clock::now() + drain_timeout;
    bool hello_complete = false;
    std::chrono::steady_clock::time_point last_data_time;
    int packet_count = 0;

    while (std::chrono::steady_clock::now() < deadline) {
      if (socket.available() == 0) {
        if (hello_complete &&
            std::chrono::steady_clock::now() - last_data_time >= kQuietMs) {
          SPDLOG_INFO(
              "WaitForServerTlsHelloAsync: quiet period elapsed, done "
              "({} bytes, {} reads)",
              data.size(), packet_count);
          co_return data;
        }
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor, kPollInterval);
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }

      const std::size_t bytes =
          co_await socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      ++packet_count;

      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        last_data_time = std::chrono::steady_clock::now();

        if (!hello_complete && IsServerHelloComplete(data)) {
          hello_complete = true;
          SPDLOG_INFO(
              "WaitForServerTlsHelloAsync: hello complete at {} bytes "
              "after {} reads, draining...",
              data.size(), packet_count);
        }
      }

      if (ec == boost::asio::error::eof) {
        SPDLOG_INFO("WaitForServerTlsHelloAsync: EOF, {} bytes", data.size());
        if (!data.empty()) co_return data;
        break;
      }
      if (ec) {
        SPDLOG_ERROR("WaitForServerTlsHelloAsync: {}", ec.message());
        break;
      }
    }

    if (!hello_complete) {
      SPDLOG_WARN(
          "WaitForServerTlsHelloAsync: timeout without complete ServerHello, "
          "{} bytes",
          data.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("WaitForServerTlsHelloAsync exception: {}", e.what());
  }
  co_return std::nullopt;
}

// ---------------------------------------------------------------------------
// WaitForClientChangeCipherSpec  (asynchronous coroutine)
//
// Reads exactly 6 bytes and validates them against the expected CCS record
// {0x14, 0x03, 0x03, 0x00, 0x01, 0x01}.
// Returns true only on exact match.
// ---------------------------------------------------------------------------
inline boost::asio::awaitable<bool> WaitForClientChangeCipherSpec(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  constexpr auto kPollInterval = std::chrono::milliseconds(50);

  const auto target_ccs = protocol::https::utils::MakeClientChangeCipherSpec();
  const std::size_t target_size = target_ccs.size();  // 6 bytes

  std::vector<std::uint8_t> buffer(target_size);
  try {
    boost::system::error_code ec;
    const auto deadline = std::chrono::steady_clock::now() + drain_timeout;
    std::size_t total_read = 0;

    while (std::chrono::steady_clock::now() < deadline) {
      if (socket.available() == 0) {
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor, kPollInterval);
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }

      const std::size_t bytes_read = co_await socket.async_read_some(
          boost::asio::buffer(
              buffer.data() + total_read, target_size - total_read),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      total_read += bytes_read;

      if (total_read == target_size) {
        const bool match = (buffer == target_ccs);
        if (!match) {
          SPDLOG_WARN("WaitForClientChangeCipherSpec: unexpected bytes");
        }
        co_return match;
      }

      if (ec == boost::asio::error::eof) break;
      if (ec) {
        SPDLOG_ERROR("WaitForClientChangeCipherSpec: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("WaitForClientChangeCipherSpec exception: {}", e.what());
  }
  co_return false;
}

// ---------------------------------------------------------------------------
// WaitForClientTlsHelloAsync  (asynchronous coroutine)
//
// Reads until a complete ClientHello record is in the buffer.
// ---------------------------------------------------------------------------
inline boost::asio::awaitable<TlsData> WaitForClientTlsHelloAsync(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  constexpr auto kPollInterval = std::chrono::milliseconds(50);

  std::vector<std::uint8_t> data;
  data.reserve(65536);

  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + drain_timeout;

    while (std::chrono::steady_clock::now() < deadline) {
      if (socket.available() == 0) {
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor, kPollInterval);
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }

      const std::size_t bytes =
          co_await socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        if (IsClientHelloComplete(data)) {
          co_return data;
        }
      }

      if (ec == boost::asio::error::eof) break;
      if (ec) {
        SPDLOG_ERROR("WaitForClientTlsHelloAsync: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("WaitForClientTlsHelloAsync exception: {}", e.what());
  }
  co_return std::nullopt;
}

}  // namespace fptn::common::network
