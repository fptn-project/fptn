/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"

#include "data/tls_real_capture_data.h"

namespace {

using fptn::common::network::SetTlsServerKeyShare;
using fptn::common::network::SetTlsServerRandom;
using fptn::testing::tls::AllRealCaptures;
using fptn::testing::tls::Bytes;

constexpr std::size_t kRandomOffset = 11;
constexpr std::size_t kKeyLen = 32;

const Bytes& RandomMarker() {
  static const Bytes kMarker(kKeyLen, 0xA5);
  return kMarker;
}

const Bytes& KeyMarker() {
  static const Bytes kMarker(kKeyLen, 0x5A);
  return kMarker;
}

std::size_t FindX25519KeyOffset(const Bytes& flight) {
  if (flight.size() < 5) {
    return 0;
  }
  const std::size_t record_end = std::min<std::size_t>(
      5 + ((static_cast<std::size_t>(flight[3]) << 8) | flight[4]),
      flight.size());
  const std::uint8_t pattern[] = {
      0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
  const auto begin = flight.begin();
  const auto it = std::search(begin, begin + record_end, std::begin(pattern),
      std::end(pattern));
  if (it == begin + record_end) {
    return 0;
  }
  const std::size_t offset =
      static_cast<std::size_t>(std::distance(begin, it)) + sizeof(pattern);
  return offset + kKeyLen <= flight.size() ? offset : 0;
}

Bytes MakeServerHello(const Bytes& key_share_body) {
  Bytes extensions = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
  extensions.insert(extensions.end(), {0x00, 0x33});
  extensions.push_back(static_cast<std::uint8_t>(key_share_body.size() >> 8));
  extensions.push_back(static_cast<std::uint8_t>(key_share_body.size()));
  extensions.insert(
      extensions.end(), key_share_body.begin(), key_share_body.end());

  Bytes body = {0x03, 0x03};
  body.insert(body.end(), kKeyLen, 0x11);
  body.push_back(kKeyLen);
  body.insert(body.end(), kKeyLen, 0x22);
  body.insert(body.end(), {0x13, 0x01});
  body.push_back(0x00);
  body.push_back(static_cast<std::uint8_t>(extensions.size() >> 8));
  body.push_back(static_cast<std::uint8_t>(extensions.size()));
  body.insert(body.end(), extensions.begin(), extensions.end());

  Bytes flight = {0x16, 0x03, 0x03};
  flight.push_back(static_cast<std::uint8_t>((body.size() + 4) >> 8));
  flight.push_back(static_cast<std::uint8_t>(body.size() + 4));
  flight.push_back(0x02);
  flight.push_back(0x00);
  flight.push_back(static_cast<std::uint8_t>(body.size() >> 8));
  flight.push_back(static_cast<std::uint8_t>(body.size()));
  flight.insert(flight.end(), body.begin(), body.end());
  return flight;
}

void ExpectOnlyRangeChanged(const Bytes& before,
    const Bytes& after,
    std::size_t offset,
    std::size_t length,
    const char* host) {
  ASSERT_EQ(before.size(), after.size()) << host;
  for (std::size_t i = 0; i < before.size(); ++i) {
    if (i >= offset && i < offset + length) {
      continue;
    }
    ASSERT_EQ(before[i], after[i])
        << host << ": byte " << i << " outside the patched range changed";
  }
}

// cppcheck-suppress syntaxError
TEST(TlsServerHelloRestamp, RealFlightsGetFreshRandom) {
  for (const auto& capture : AllRealCaptures()) {
    Bytes patched = capture.flight;
    ASSERT_TRUE(SetTlsServerRandom(patched, RandomMarker())) << capture.host;
    EXPECT_TRUE(std::equal(RandomMarker().begin(), RandomMarker().end(),
        patched.begin() + kRandomOffset))
        << capture.host;
    ExpectOnlyRangeChanged(
        capture.flight, patched, kRandomOffset, kKeyLen, capture.host);
  }
}

TEST(TlsServerHelloRestamp, RealFlightsGetFreshKeyShare) {
  std::size_t patched_hosts = 0;
  for (const auto& capture : AllRealCaptures()) {
    const std::size_t expected = FindX25519KeyOffset(capture.flight);
    Bytes patched = capture.flight;
    const bool done = SetTlsServerKeyShare(patched, KeyMarker());

    ASSERT_EQ(done, expected != 0)
        << capture.host << ": disagreement with the independent scan";
    if (!done) {
      EXPECT_EQ(capture.flight, patched) << capture.host;
      continue;
    }
    ++patched_hosts;
    EXPECT_TRUE(std::equal(
        KeyMarker().begin(), KeyMarker().end(), patched.begin() + expected))
        << capture.host << ": key not written at the scanned offset";
    ExpectOnlyRangeChanged(
        capture.flight, patched, expected, kKeyLen, capture.host);
  }
  EXPECT_GT(patched_hosts, 0U) << "no x25519 capture in the corpus";
}

TEST(TlsServerHelloRestamp, ClientHelloIsRejected) {
  for (const auto& capture : AllRealCaptures()) {
    Bytes random_target = capture.client_hello;
    Bytes key_target = capture.client_hello;
    EXPECT_FALSE(SetTlsServerRandom(random_target, RandomMarker()))
        << capture.host;
    EXPECT_FALSE(SetTlsServerKeyShare(key_target, KeyMarker())) << capture.host;
    EXPECT_EQ(capture.client_hello, random_target) << capture.host;
    EXPECT_EQ(capture.client_hello, key_target) << capture.host;
  }
}

TEST(TlsServerHelloRestamp, TruncatedFlightsStayInsideTheirBuffer) {
  for (const auto& capture : AllRealCaptures()) {
    const std::size_t key_offset = FindX25519KeyOffset(capture.flight);
    for (std::size_t len = 0; len <= capture.flight.size(); ++len) {
      const Bytes prefix(capture.flight.begin(), capture.flight.begin() + len);

      Bytes random_target = prefix;
      const bool random_done =
          SetTlsServerRandom(random_target, RandomMarker());
      ASSERT_EQ(random_target.size(), len) << capture.host << " len=" << len;
      ASSERT_EQ(random_done, len >= kRandomOffset + kKeyLen)
          << capture.host << " len=" << len;
      ExpectOnlyRangeChanged(
          prefix, random_target, kRandomOffset, kKeyLen, capture.host);

      Bytes key_target = prefix;
      const bool key_done = SetTlsServerKeyShare(key_target, KeyMarker());
      ASSERT_EQ(key_target.size(), len) << capture.host << " len=" << len;
      ASSERT_EQ(key_done, key_offset != 0 && len >= key_offset + kKeyLen)
          << capture.host << " len=" << len;
      ExpectOnlyRangeChanged(
          prefix, key_target, key_offset, key_done ? kKeyLen : 0, capture.host);
    }
  }
}

TEST(TlsServerHelloRestamp, GarbageNeverResizesOrCrashes) {
  std::mt19937 rng(20260905);  // NOLINT(bugprone-random-generator-seed)
  std::uniform_int_distribution<int> byte(0, 255);
  std::uniform_int_distribution<std::size_t> length(0, 400);

  for (int i = 0; i < 20000; ++i) {
    Bytes data(length(rng));
    for (auto& value : data) {
      value = static_cast<std::uint8_t>(byte(rng));
    }
    if (data.size() > 5 && (i % 2) == 0) {
      data[5] = 0x02;
    }
    const Bytes original = data;

    SetTlsServerRandom(data, RandomMarker());
    SetTlsServerKeyShare(data, KeyMarker());
    ASSERT_EQ(data.size(), original.size()) << "iteration " << i;
  }
}

TEST(TlsServerHelloRestamp, NonX25519KeyShareIsLeftAlone) {
  Bytes p256_body = {0x00, 0x17, 0x00, 0x41};
  p256_body.insert(p256_body.end(), 65, 0x04);
  Bytes p256 = MakeServerHello(p256_body);
  const Bytes p256_original = p256;
  EXPECT_FALSE(SetTlsServerKeyShare(p256, KeyMarker()));
  EXPECT_EQ(p256_original, p256);

  Bytes retry = MakeServerHello({0x00, 0x1d});
  const Bytes retry_original = retry;
  EXPECT_FALSE(SetTlsServerKeyShare(retry, KeyMarker()));
  EXPECT_EQ(retry_original, retry);

  Bytes x25519_body = {0x00, 0x1d, 0x00, 0x20};
  x25519_body.insert(x25519_body.end(), kKeyLen, 0x33);
  Bytes x25519 = MakeServerHello(x25519_body);
  EXPECT_TRUE(SetTlsServerKeyShare(x25519, KeyMarker()));
}

TEST(TlsServerHelloRestamp, WrongReplacementSizeIsRejected) {
  const auto& capture = AllRealCaptures().front();
  Bytes target = capture.flight;
  EXPECT_FALSE(SetTlsServerRandom(target, Bytes(31, 0xFF)));
  EXPECT_FALSE(SetTlsServerRandom(target, Bytes(33, 0xFF)));
  EXPECT_FALSE(SetTlsServerKeyShare(target, Bytes(31, 0xFF)));
  EXPECT_FALSE(SetTlsServerKeyShare(target, Bytes(33, 0xFF)));
  EXPECT_EQ(capture.flight, target);
}

}  // namespace
