/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <jwt-cpp/base.h>     // NOLINT(build/include_order)
#include <jwt-cpp/jwt.h>      // NOLINT(build/include_order)
#include <nlohmann/json.hpp>  // NOLINT(build/include_order)
#include <openssl/evp.h>      // NOLINT(build/include_order)
#include <openssl/pem.h>      // NOLINT(build/include_order)
#include <openssl/x509.h>     // NOLINT(build/include_order)

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/jwt_token/token_manager.h"

namespace {

constexpr const char* kUsername = "test-user";
constexpr int kBandwidthBit = 100500;

struct Pem {
  std::string key;
  std::string crt;
};

std::string BioToString(BIO* bio) {
  char* data = nullptr;
  const auto len = BIO_get_mem_data(bio, &data);
  return std::string(data, static_cast<std::size_t>(len));
}

Pem GenerateSelfSigned() {
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);

  X509* crt = X509_new();
  ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
  X509_gmtime_adj(X509_getm_notBefore(crt), 0);
  X509_gmtime_adj(X509_getm_notAfter(crt), 60 * 60 * 24 * 365);
  X509_set_pubkey(crt, pkey);
  X509_NAME* name = X509_get_subject_name(crt);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
      reinterpret_cast<const unsigned char*>("fptn-test"), -1, -1, 0);
  X509_set_issuer_name(crt, name);
  X509_sign(crt, pkey, EVP_sha256());

  Pem pem;
  BIO* key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(
      key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  pem.key = BioToString(key_bio);
  BIO_free(key_bio);

  BIO* crt_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(crt_bio, crt);
  pem.crt = BioToString(crt_bio);
  BIO_free(crt_bio);

  X509_free(crt);
  EVP_PKEY_free(pkey);
  return pem;
}

const Pem& ServerPem() {
  static const Pem kPem = GenerateSelfSigned();
  return kPem;
}

const Pem& AttackerPem() {
  static const Pem kPem = GenerateSelfSigned();
  return kPem;
}

std::string MakeToken(const std::string& signing_key,
    const std::string& issuer,
    std::chrono::system_clock::time_point expires_at,
    const std::string& username = kUsername,
    int bandwidth_bit = kBandwidthBit) {
  const auto now = std::chrono::system_clock::now();
  return jwt::create<jwt::traits::nlohmann_json>()
      .set_issuer(issuer)
      .set_type("JWT")
      .set_id("fptn")
      .set_issued_at(now - std::chrono::hours(1))
      .set_expires_at(expires_at)
      .set_payload_claim("username", username)
      .set_payload_claim("bandwidth_bit", bandwidth_bit)
      .sign(jwt::algorithm::rs256("", signing_key, "", ""));
}

std::string TamperBandwidth(const std::string& token, int new_value) {
  const auto first = token.find('.');
  const auto second = token.find('.', first + 1);
  const std::string header = token.substr(0, first);
  const std::string payload = token.substr(first + 1, second - first - 1);
  const std::string signature = token.substr(second + 1);

  auto json = nlohmann::json::parse(jwt::base::decode<jwt::alphabet::base64url>(
      jwt::base::pad<jwt::alphabet::base64url>(payload)));
  json["bandwidth_bit"] = new_value;

  const std::string tampered = jwt::base::trim<jwt::alphabet::base64url>(
      jwt::base::encode<jwt::alphabet::base64url>(json.dump()));
  return header + "." + tampered + "." + signature;
}

class TokenManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ =
        std::filesystem::temp_directory_path() /
        ("fptn-jwt-" +
            std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir_);
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);
  }

  fptn::common::jwt_token::TokenManager MakeManager(
      const std::string& crt, const std::string& key) {
    const auto crt_path = dir_ / "server.crt";
    const auto key_path = dir_ / "server.key";
    WriteFile(crt_path, crt);
    WriteFile(key_path, key);
    return fptn::common::jwt_token::TokenManager(
        crt_path.string(), key_path.string());
  }

  fptn::common::jwt_token::TokenManager MakeServerManager() {
    return MakeManager(ServerPem().crt, ServerPem().key);
  }

  static void WriteFile(
      const std::filesystem::path& path, const std::string& content) {
    std::ofstream os(path, std::ios::binary);
    os << content;
  }

  std::filesystem::path dir_;
};

}  // namespace

TEST_F(TokenManagerTest, GeneratedTokenIsAccepted) {
  const auto manager = MakeServerManager();
  const auto token = manager.Generate(kUsername, kBandwidthBit).first;

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_TRUE(manager.Validate(token, username, bandwidth_bit));
  EXPECT_EQ(username, kUsername);
  EXPECT_EQ(bandwidth_bit, static_cast<std::size_t>(kBandwidthBit));
}

TEST_F(TokenManagerTest, TokenSignedByForeignKeyIsRejected) {
  const auto manager = MakeServerManager();
  const auto token = MakeToken(AttackerPem().key, "auth0",
      std::chrono::system_clock::now() + std::chrono::hours(24));

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate(token, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, TamperedPayloadIsRejected) {
  const auto manager = MakeServerManager();
  const auto token = manager.Generate(kUsername, kBandwidthBit).first;
  const auto tampered = TamperBandwidth(token, 1000000000);

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate(tampered, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, UnsignedTokenIsRejected) {
  const auto manager = MakeServerManager();
  const auto token = jwt::create<jwt::traits::nlohmann_json>()
                         .set_issuer("auth0")
                         .set_type("JWT")
                         .set_id("fptn")
                         .set_issued_at(std::chrono::system_clock::now())
                         .set_expires_at(std::chrono::system_clock::now() +
                                         std::chrono::hours(24))
                         .set_payload_claim("username", std::string(kUsername))
                         .set_payload_claim("bandwidth_bit", kBandwidthBit)
                         .sign(jwt::algorithm::none());

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate(token, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, ExpiredTokenIsRejected) {
  const auto manager = MakeServerManager();
  const auto token = MakeToken(ServerPem().key, "auth0",
      std::chrono::system_clock::now() - std::chrono::minutes(1));

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate(token, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, ForeignIssuerIsRejected) {
  const auto manager = MakeServerManager();
  const auto token = MakeToken(ServerPem().key, "evil-issuer",
      std::chrono::system_clock::now() + std::chrono::hours(24));

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate(token, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, MalformedTokenIsRejected) {
  const auto manager = MakeServerManager();

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_FALSE(manager.Validate("", username, bandwidth_bit));
  EXPECT_FALSE(manager.Validate("not.a.token", username, bandwidth_bit));
}

TEST_F(TokenManagerTest, FullChainCertificateIsAccepted) {
  const auto manager =
      MakeManager(ServerPem().crt + AttackerPem().crt, ServerPem().key);
  const auto token = manager.Generate(kUsername, kBandwidthBit).first;

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_TRUE(manager.Validate(token, username, bandwidth_bit));
}

TEST_F(TokenManagerTest, CertificateWithLeadingBlankLineIsAccepted) {
  const auto manager = MakeManager("\n" + ServerPem().crt, ServerPem().key);
  const auto token = manager.Generate(kUsername, kBandwidthBit).first;

  std::string username;
  std::size_t bandwidth_bit = 0;
  EXPECT_TRUE(manager.Validate(token, username, bandwidth_bit));
}
