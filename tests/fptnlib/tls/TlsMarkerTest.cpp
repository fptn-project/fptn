/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/time/time_provider.h"

namespace {

namespace utils = fptn::protocol::https::utils;

constexpr std::size_t kSessionLen = 32;
constexpr std::size_t kFptnClientMarkerOffset = kSessionLen - 4;  // 28
constexpr std::size_t kDecoyMarkerOffset = 10;
constexpr std::size_t kDecoyMarkerOffset2 = 14;

std::string ToHex(const std::string& s) {
  static const char* h = "0123456789abcdef";
  std::string o;
  for (unsigned char c : s) {
    o.push_back(h[c >> 4]);
    o.push_back(h[c & 0x0F]);
  }
  return o;
}

// A 32-byte session_id with `marker` placed at `offset`.
std::array<std::uint8_t, kSessionLen> MakeSessionId(
    const std::string& marker, std::size_t offset) {
  std::array<std::uint8_t, kSessionLen> id{};
  std::memcpy(id.data() + offset, marker.data(), marker.size());
  return id;
}

std::uint32_t Now() {
  return fptn::time::TimeProvider::Instance()->NowTimestamp();
}

}  // namespace

// The keyed marker matches an independently computed HMAC-SHA256 reference
// (see the same vectors in Python: hmac.new(S, be32(ts), sha256)[:4]).
TEST(TlsMarker, KeyedMatchesReferenceVectors) {
  EXPECT_EQ(ToHex(utils::GenerateFptnKeyKeyed(1700000000, "test-shared-secret")),
      "486cd553");
  EXPECT_EQ(ToHex(utils::GenerateFptnKeyKeyed(1700000000, "S1")), "88a221b0");
  EXPECT_EQ(ToHex(utils::GenerateFptnKeyKeyed(1700000000, "S2")), "1425e0a1");
  // Legacy marker is the unkeyed SHA1(be32(ts))[:4].
  EXPECT_EQ(ToHex(utils::GenerateFptnKey(1700000000)), "f18b7fe9");
}

TEST(TlsMarker, KeyedProperties) {
  EXPECT_EQ(utils::GenerateFptnKeyKeyed(1700000000, "S1").size(), 4u);
  EXPECT_NE(utils::GenerateFptnKeyKeyed(1700000000, "S1"),
      utils::GenerateFptnKey(1700000000));
  EXPECT_NE(utils::GenerateFptnKeyKeyed(1700000000, "S1"),
      utils::GenerateFptnKeyKeyed(1700000000, "S2"));
  EXPECT_EQ(utils::GenerateFptnKeyKeyed(1700000000, "S1"),
      utils::GenerateFptnKeyKeyed(1700000000, "S1"));
  EXPECT_NE(utils::GenerateFptnKeyKeyed(1700000000, "S1"),
      utils::GenerateFptnKeyKeyed(1700000005, "S1"));
}

// Server-side validation of the primary (obfuscation-less) client marker.
TEST(TlsMarker, ServerValidatesFptnClientMarker) {
  const std::string kSecret = "test-shared-secret";
  const std::uint32_t now = Now();

  const auto keyed =
      MakeSessionId(utils::GenerateFptnKeyKeyed(now, kSecret),
          kFptnClientMarkerOffset);
  const auto legacy =
      MakeSessionId(utils::GenerateFptnKey(now), kFptnClientMarkerOffset);

  // keyed marker accepted when the secret is known (with or without legacy).
  EXPECT_TRUE(utils::IsFptnClientSessionID(
      keyed.data(), keyed.size(), {kSecret}, true));
  EXPECT_TRUE(utils::IsFptnClientSessionID(
      keyed.data(), keyed.size(), {kSecret}, false));
  // wrong / missing secret rejected.
  EXPECT_FALSE(utils::IsFptnClientSessionID(
      keyed.data(), keyed.size(), {"other"}, false));
  EXPECT_FALSE(
      utils::IsFptnClientSessionID(keyed.data(), keyed.size(), {}, false));

  // legacy marker: accepted only while accept_legacy is on.
  EXPECT_TRUE(utils::IsFptnClientSessionID(
      legacy.data(), legacy.size(), {kSecret}, true));
  EXPECT_FALSE(utils::IsFptnClientSessionID(
      legacy.data(), legacy.size(), {kSecret}, false));
  // pure-legacy deployment (no keys configured) keeps working.
  EXPECT_TRUE(
      utils::IsFptnClientSessionID(legacy.data(), legacy.size(), {}, true));
}

// Key rotation: server accepts any of several configured keys.
TEST(TlsMarker, ServerAcceptsRotatedKeys) {
  const std::uint32_t now = Now();
  const std::vector<std::string> keys{"S1", "S2"};
  for (const auto& k : keys) {
    const auto id =
        MakeSessionId(utils::GenerateFptnKeyKeyed(now, k),
            kFptnClientMarkerOffset);
    EXPECT_TRUE(utils::IsFptnClientSessionID(id.data(), id.size(), keys, false))
        << "rotated key not accepted: " << k;
  }
}

// The two decoy/reality marker positions validate the same way.
TEST(TlsMarker, ServerValidatesDecoyMarkers) {
  const std::string kSecret = "test-shared-secret";
  const std::uint32_t now = Now();

  const auto decoy1 =
      MakeSessionId(utils::GenerateFptnKeyKeyed(now, kSecret),
          kDecoyMarkerOffset);
  EXPECT_TRUE(utils::IsDecoyHandshakeSessionID(
      decoy1.data(), decoy1.size(), {kSecret}, false));
  EXPECT_FALSE(utils::IsDecoyHandshakeSessionID(
      decoy1.data(), decoy1.size(), {"other"}, false));

  const auto decoy2 =
      MakeSessionId(utils::GenerateFptnKeyKeyed(now, kSecret),
          kDecoyMarkerOffset2);
  EXPECT_TRUE(utils::IsDecoyHandshakeSessionID2(
      decoy2.data(), decoy2.size(), {kSecret}, false));
  EXPECT_FALSE(utils::IsDecoyHandshakeSessionID2(
      decoy2.data(), decoy2.size(), {"other"}, false));
}
