/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/utils/tls/tls.h"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <openssl/evp.h>    // NOLINT(build/include_order)
#include <openssl/md5.h>    // NOLINT(build/include_order)
#include <openssl/rand.h>   // NOLINT(build/include_order)
#include <openssl/sha.h>    // NOLINT(build/include_order)
#include <openssl/ssl.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/time/time_provider.h"

namespace fptn::protocol::https::utils {

constexpr int kSessionLen = 32;
constexpr std::size_t kFptnKeyLength = 4;
constexpr int kDecoyHandshakeSessionIDShift = 10;
constexpr int kDecoyHandshakeSessionIDShift2 = 14;

std::string GetSHA1Hash(std::uint32_t number) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    return {};
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA1");
  if (!md) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  if (!EVP_DigestUpdate(mdctx, &number, sizeof(number))) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  unsigned int outlen = 0;
  unsigned char buffer[EVP_MAX_MD_SIZE] = {0};
  if (!EVP_DigestFinal_ex(mdctx, buffer, &outlen)) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }
  EVP_MD_CTX_free(mdctx);
  return std::string(reinterpret_cast<const char*>(buffer), outlen);
}

std::string GenerateFptnKey(std::uint32_t timestamp) {
  std::string result = GetSHA1Hash(htonl(timestamp));
  if (result.size() > kFptnKeyLength) {  //  key len
    return result.substr(0, kFptnKeyLength);
  }
  throw boost::beast::system_error(
      boost::beast::error_code(static_cast<int>(::ERR_get_error()),
          boost::asio::error::get_ssl_category()),
      "Error generate Session ID");
}

bool SetDecoyHandshakeSessionID(SSL* ssl) {
  // random
  std::uint8_t session_id[kSessionLen] = {0};
  if (::RAND_bytes(session_id, sizeof(session_id)) != 1) {
    return false;
  }

  // copy timestamp
  const auto timestamp = fptn::time::TimeProvider::Instance()->NowTimestamp();
  const std::string key = GenerateFptnKey(timestamp);
  std::memcpy(
      &session_id[kDecoyHandshakeSessionIDShift], key.c_str(), key.size());
  return 0 != ::SSL_set_tls_hello_custom_session_id(
                  ssl, session_id, sizeof(session_id));
}

bool IsDecoyHandshakeSessionID(
    const std::uint8_t* session, std::size_t session_len) {
  (void)session_len;
  char data[kFptnKeyLength] = {0};
  std::memcpy(&data, &session[kDecoyHandshakeSessionIDShift], sizeof(data));
  const std::string recv_key(data, sizeof(data));

  const auto now_timestamp =
      fptn::time::TimeProvider::Instance()->NowTimestamp();

  constexpr std::uint32_t kTimeShiftSeconds = 10;  // ten seconds

  const std::uint32_t timestamp = now_timestamp + (kTimeShiftSeconds / 2);

  for (std::uint32_t shift = 0; shift <= kTimeShiftSeconds; shift++) {
    const std::string key = GenerateFptnKey(timestamp - shift);
    if (recv_key == key) {
      return true;
    }
  }
  return false;
}

bool IsDecoyHandshakeSessionID2(
    const std::uint8_t* session, std::size_t session_len) {
  (void)session_len;
  char data[kFptnKeyLength] = {0};
  std::memcpy(&data, &session[kDecoyHandshakeSessionIDShift2], sizeof(data));
  const std::string recv_key(data, sizeof(data));

  const auto now_timestamp =
      fptn::time::TimeProvider::Instance()->NowTimestamp();

  constexpr std::uint32_t kTimeShiftSeconds = 10;  // ten seconds

  const std::uint32_t timestamp = now_timestamp + (kTimeShiftSeconds / 2);

  for (std::uint32_t shift = 0; shift <= kTimeShiftSeconds; shift++) {
    const std::string key = GenerateFptnKey(timestamp - shift);
    if (recv_key == key) {
      return true;
    }
  }
  return false;
}

bool SetHandshakeSessionID(SSL* ssl) {
  // random
  std::uint8_t session_id[kSessionLen] = {0};
  if (::RAND_bytes(session_id, sizeof(session_id)) != 1) {
    return false;
  }
  // copy timestamp
  const auto timestamp = fptn::time::TimeProvider::Instance()->NowTimestamp();

  const std::string key = GenerateFptnKey(timestamp);
  std::memcpy(&session_id[kSessionLen - key.size()], key.c_str(), key.size());

  return 0 != ::SSL_set_tls_hello_custom_session_id(
                  ssl, session_id, sizeof(session_id));
}

bool IsFptnClientSessionID(
    const std::uint8_t* session, std::size_t session_len) {
  char data[kFptnKeyLength] = {0};
  std::memcpy(&data, &session[session_len - sizeof(data)], sizeof(data));
  const std::string recv_key(data, sizeof(data));

  const auto now_timestamp =
      fptn::time::TimeProvider::Instance()->NowTimestamp();

  constexpr std::uint32_t kTimeShiftSeconds = 10;  // ten seconds

  const std::uint32_t timestamp = now_timestamp + (kTimeShiftSeconds / 2);

  for (std::uint32_t shift = 0; shift <= kTimeShiftSeconds; shift++) {
    const std::string key = GenerateFptnKey(timestamp - shift);
    if (recv_key == key) {
      return true;
    }
  }
  return false;
}

bool SetHandshakeSni(SSL* ssl, const std::string& sni) {
  // Set SNI (Server Name)
  if (1 != ::SSL_set_tlsext_host_name(ssl, sni.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set SNI "{}")", sni));
  }
  // Add Chrome-like padding (to match packet size)
  SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
  return true;
}

SSL_CTX* CreateNewSslCtx() {
  SSL_CTX* handle = ::SSL_CTX_new(::TLS_client_method());
  if (!handle) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to create SSL context");
  }

  if (0 == ::SSL_CTX_set_min_proto_version(handle, TLS1_2_VERSION)) {
    ::SSL_CTX_free(handle);
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to set min TLS version");
  }

  if (0 == ::SSL_CTX_set_max_proto_version(handle, TLS1_3_VERSION)) {
    ::SSL_CTX_free(handle);
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to set max TLS version");
  }

  SSL_CTX_set_grease_enabled(handle, 1);
  SSL_CTX_enable_ocsp_stapling(handle);
  SSL_CTX_enable_signed_cert_timestamps(handle);

  // Set ciphers ТОЧНО КАК В RUST КОДЕ
  const std::string ciphers_list = ChromeCiphers();
  if (0 == ::SSL_CTX_set_cipher_list(handle, ciphers_list.c_str())) {
    ::SSL_CTX_free(handle);
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to set ciphers");
  }

  const char* groups = "X25519MLKEM768:X25519:secp256r1:secp384r1";
  SSL_CTX_set1_groups_list(handle, groups);

  static unsigned char alpn[] = {
      0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  if (0 != ::SSL_CTX_set_alpn_protos(handle, alpn, sizeof(alpn))) {
    ::SSL_CTX_free(handle);
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to set ALPN");
  }

  const std::string sigalgs_list =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512";

  if (1 != SSL_CTX_set1_sigalgs_list(handle, sigalgs_list.c_str())) {
    ::SSL_CTX_free(handle);
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        "Failed to set signature algorithms");
  }

  SSL_CTX_set_mode(handle, SSL_MODE_RELEASE_BUFFERS);
  return handle;
}

std::string ChromeCiphers() {
  return "TLS_AES_128_GCM_SHA256:"
         "TLS_AES_256_GCM_SHA384:"
         "TLS_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
         "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
         "TLS_RSA_WITH_AES_128_GCM_SHA256:"
         "TLS_RSA_WITH_AES_256_GCM_SHA384:"
         "TLS_RSA_WITH_AES_128_CBC_SHA:"
         "TLS_RSA_WITH_AES_256_CBC_SHA";
}

std::string GetCertificateMD5Fingerprint(const X509* cert) {
  unsigned char md[MD5_DIGEST_LENGTH] = {};
  if (X509_digest(cert, EVP_md5(), md, nullptr) != 1) {
    SPDLOG_ERROR("Failed to compute MD5 digest");
    return {};
  }

  std::stringstream ss;
  // NOLINTNEXTLINE(modernize-loop-convert)
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(md[i]);
  }
  return ss.str();
}

std::vector<std::uint8_t> GenerateDecoyTlsHandshake(const std::string& sni) {
  std::vector<std::uint8_t> handshake_data;
  try {
    SSL_CTX* ssl_ctx = CreateNewSslCtx();
    SSL* ssl = ::SSL_new(ssl_ctx);

    BIO* bio_out = ::BIO_new(BIO_s_mem());
    BIO* bio_in = ::BIO_new(BIO_s_mem());
    ::SSL_set_bio(ssl, bio_in, bio_out);

    SetHandshakeSni(ssl, sni);
    SetDecoyHandshakeSessionID(ssl);
    // X25519MLKEM768 (ctx default) triggers HelloRetryRequest on servers
    // that don't support post-quantum key exchange, deadlocking the decoy read.
    ::SSL_set1_groups_list(ssl, "X25519:secp256r1:secp384r1");

    ::SSL_set_connect_state(ssl);

    int handshake_result;
    int retry_count = 0;
    constexpr int kMaxRetries = 10;

    do {
      handshake_result = ::SSL_do_handshake(ssl);

      char* bio_data = nullptr;
      auto bio_length = ::BIO_get_mem_data(bio_out, &bio_data);

      if (bio_data && bio_length > 0) {
        handshake_data.insert(
            handshake_data.end(), bio_data, bio_data + bio_length);
        BIO_reset(bio_out);
      }
      retry_count++;
    } while (handshake_result <= 0 &&
             SSL_get_error(ssl, handshake_result) == SSL_ERROR_WANT_WRITE &&
             retry_count < kMaxRetries);

    if (handshake_data.empty()) {
      SPDLOG_WARN("No handshake data was generated for SNI: {}", sni);
    } else {
      SPDLOG_INFO(
          "Successfully generated {} bytes of TLS handshake for SNI: {}",
          handshake_data.size(), sni);
    }
    ::SSL_free(ssl);
    ::SSL_CTX_free(ssl_ctx);
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "GenerateTlsHandshake exception for SNI {}: {}", sni, e.what());
  }
  return handshake_data;
}

std::optional<std::array<std::uint8_t, 32>> GenerateDecoyTlsSessionId() {
  std::array<std::uint8_t, kSessionLen> session_id{};
  if (::RAND_bytes(session_id.data(), session_id.size()) != 1) {
    return std::nullopt;
  }

  // Get timestamp and generate key
  const auto timestamp = fptn::time::TimeProvider::Instance()->NowTimestamp();
  const std::string key = GenerateFptnKey(timestamp);
  const std::size_t copy_size =
      std::min(key.size(), session_id.size() - kDecoyHandshakeSessionIDShift);
  std::memcpy(session_id.data() + kDecoyHandshakeSessionIDShift, key.c_str(),
      copy_size);
  return session_id;
}

std::optional<std::array<std::uint8_t, 32>> GenerateDecoyTlsSessionId2() {
  std::array<std::uint8_t, kSessionLen> session_id{};
  if (::RAND_bytes(session_id.data(), session_id.size()) != 1) {
    return std::nullopt;
  }

  // Get timestamp and generate key
  const auto timestamp = fptn::time::TimeProvider::Instance()->NowTimestamp();
  const std::string key = GenerateFptnKey(timestamp);
  const std::size_t copy_size =
      std::min(key.size(), session_id.size() - kDecoyHandshakeSessionIDShift2);
  std::memcpy(session_id.data() + kDecoyHandshakeSessionIDShift2, key.c_str(),
      copy_size);
  return session_id;
}

// MAYBE IT WILL REFACTOR
namespace {
std::unordered_map<SSL*, CertificateVerificationCallback*> attach_callbacks;
std::mutex attach_callback_mutex;
}  // namespace

void AttachCertificateVerificationCallback(
    SSL* ssl, const CertificateVerificationCallback& callback) {
  auto* func_ptr = new CertificateVerificationCallback(callback);
  {
    const std::scoped_lock lock(attach_callback_mutex);  // mutex
    attach_callbacks[ssl] = func_ptr;
  }

  ::SSL_set_verify(
      ssl, SSL_VERIFY_PEER, [](int preverified, X509_STORE_CTX* ctx) -> int {
        (void)preverified;

        const X509* cert = ::X509_STORE_CTX_get_current_cert(ctx);
        if (!cert) {
          return 0;
        }

        SSL* ssl = static_cast<SSL*>(::X509_STORE_CTX_get_ex_data(
            ctx, ::SSL_get_ex_data_X509_STORE_CTX_idx()));
        if (!ssl) {
          return 0;
        }

        const std::string md5_fingerprint = GetCertificateMD5Fingerprint(cert);
        if (md5_fingerprint.empty()) {
          return 0;
        }

        const std::scoped_lock lock(attach_callback_mutex);  // mutex
        {
          const auto it = attach_callbacks.find(ssl);
          if (it == attach_callbacks.end()) {
            return 0;
          }
          return (it->second && (*it->second)(md5_fingerprint) ? 1 : 0);
        }
      });
}

void AttachCertificateVerificationCallbackDelete(SSL* ssl) {
  const std::scoped_lock lock(attach_callback_mutex);  // mutex

  auto it = attach_callbacks.find(ssl);
  if (it != attach_callbacks.end()) {
    delete it->second;  // Clean up the allocated callback
    attach_callbacks.erase(it);
  }
}

}  // namespace fptn::protocol::https::utils
