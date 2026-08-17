/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"
#include "common/network/utils.h"

#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/https/utils/change_cipher_spec.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/time/time_provider.h"

#include "data/tls_real_capture_data.h"

namespace {

using fptn::common::network::GetTlsSessionId;
using fptn::common::network::GetTlsSNI;
using fptn::common::network::IsClientHelloComplete;
using fptn::common::network::IsServerHelloComplete;
using fptn::common::network::IsTlsClientHello;
using fptn::common::network::kMinTls13ServerFlightAppDataBytes;
using fptn::testing::tls::AllRealCaptures;

struct RecordInfo {
  std::uint8_t content_type;
  std::size_t offset;
  std::size_t total_len;
};

std::vector<RecordInfo> SplitRecords(const std::vector<std::uint8_t>& data) {
  std::vector<RecordInfo> out;
  std::size_t pos = 0;
  while (pos + 5 <= data.size()) {
    const std::size_t len =
        (static_cast<std::size_t>(data[pos + 3]) << 8) | data[pos + 4];
    if (pos + 5 + len > data.size()) {
      break;
    }
    out.push_back(RecordInfo{.content_type = data[pos],
        .offset = pos,
        .total_len = 5 + len});
    pos += 5 + len;
  }
  return out;
}

std::size_t AppDataRecordCount(const std::vector<std::uint8_t>& data) {
  const auto records = SplitRecords(data);
  return static_cast<std::size_t>(std::count_if(records.begin(), records.end(),
      [](const RecordInfo& r) { return r.content_type == 23; }));
}

std::size_t FirstCompleteAt(const std::vector<std::uint8_t>& flight) {
  for (std::size_t n = 1; n <= flight.size(); ++n) {
    if (IsServerHelloComplete(
            std::vector<std::uint8_t>(flight.begin(), flight.begin() + n))) {
      return n;
    }
  }
  return 0;
}

std::vector<std::uint8_t> Prefix(
    const std::vector<std::uint8_t>& data, std::size_t n) {
  return std::vector<std::uint8_t>(data.begin(), data.begin() + n);
}

}  // namespace

TEST(TlsClientHelloTest, RecognisedParsedAndSniExtracted) {
  ASSERT_GE(AllRealCaptures().size(), 40U);
  for (const auto& c : AllRealCaptures()) {
    EXPECT_TRUE(IsTlsClientHello(c.client_hello.data(), c.client_hello.size()))
        << c.host;
    EXPECT_TRUE(IsClientHelloComplete(c.client_hello)) << c.host;

    const auto sni = GetTlsSNI(c.client_hello.data(), c.client_hello.size());
    ASSERT_TRUE(sni.has_value()) << c.host;
    EXPECT_EQ(sni.value(), std::string(c.host)) << c.host;

    const auto sid =
        GetTlsSessionId(c.client_hello.data(), c.client_hello.size());
    EXPECT_EQ(sid.size(), 32U) << c.host;
  }
}

TEST(TlsClientHelloTest, NeverCompleteOnAnyShortPrefix) {
  for (const auto& c : AllRealCaptures()) {
    for (std::size_t n = 1; n < c.client_hello.size(); ++n) {
      EXPECT_FALSE(IsClientHelloComplete(Prefix(c.client_hello, n)))
          << c.host << " at " << n << " of " << c.client_hello.size();
    }
  }
}

TEST(TlsServerFlightTest, CompleteWhenFullyReceived) {
  for (const auto& c : AllRealCaptures()) {
    EXPECT_TRUE(IsServerHelloComplete(c.flight))
        << c.host << " (" << c.flight.size() << " bytes, "
        << SplitRecords(c.flight).size() << " records)";
  }
}

TEST(TlsServerFlightTest, EveryCaptureIsWellFormedTls13) {
  for (const auto& c : AllRealCaptures()) {
    const auto records = SplitRecords(c.flight);
    ASSERT_FALSE(records.empty()) << c.host;
    EXPECT_EQ(records.back().offset + records.back().total_len, c.flight.size())
        << c.host << " does not end on a record boundary";
    EXPECT_EQ(records.front().content_type, 22) << c.host;
    EXPECT_GE(AppDataRecordCount(c.flight), 1U) << c.host;
  }
}

TEST(TlsServerFlightTest, SingleAppDataFlightCompletesExactlyAtEnd) {
  std::size_t checked = 0;
  for (const auto& c : AllRealCaptures()) {
    if (AppDataRecordCount(c.flight) != 1) {
      continue;
    }
    ++checked;
    EXPECT_EQ(FirstCompleteAt(c.flight), c.flight.size()) << c.host;
  }
  EXPECT_GT(checked, 0U);
}

TEST(TlsServerFlightTest, NotCompleteAtIntermediateRealSegmentBoundaries) {
  for (const auto& c : AllRealCaptures()) {
    std::size_t offset = 0;
    for (std::size_t i = 0; i + 1 < c.chunk_sizes.size(); ++i) {
      offset += c.chunk_sizes[i];
      if (!IsServerHelloComplete(Prefix(c.flight, offset))) {
        continue;
      }
      const std::size_t lost = c.flight.size() - offset;
      EXPECT_LT(lost, kMinTls13ServerFlightAppDataBytes)
          << c.host << ": complete after recv #" << (i + 1) << ", losing "
          << lost << " of " << c.flight.size() << " bytes";
    }
  }
}

TEST(TlsServerFlightTest, TruncatedFlightIsNeverAcceptedAsComplete) {
  for (const auto& c : AllRealCaptures()) {
    const auto records = SplitRecords(c.flight);
    for (const auto& r : records) {
      if (r.total_len < 2) {
        continue;
      }
      const std::size_t mid = r.offset + (r.total_len / 2);
      if (mid == 0 || mid >= c.flight.size()) {
        continue;
      }
      EXPECT_FALSE(IsServerHelloComplete(Prefix(c.flight, mid)))
          << c.host << ": accepted a buffer ending inside a record at " << mid;
    }
  }
}

TEST(TlsServerFlightTest, ParsingStaysCheapEnoughForTheReadLoop) {
  const auto start = std::chrono::steady_clock::now();
  std::size_t sink = 0;
  for (const auto& c : AllRealCaptures()) {
    std::size_t offset = 0;
    for (const auto& chunk : c.chunk_sizes) {
      offset += chunk;
      sink += IsServerHelloComplete(Prefix(c.flight, offset)) ? 1 : 0;
    }
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  EXPECT_LT(elapsed.count(), 200) << "parsed " << AllRealCaptures().size()
                                  << " flights in " << elapsed.count() << " ms";
  EXPECT_GT(sink, 0U);
}

TEST(RealityResyncTest, ObfuscatorSkipsLeftoverDecoyBytesOfEveryLength) {
  const std::vector<std::uint8_t> payload = {'f', 'p', 't', 'n', 0x00, 0xff};

  for (const auto& c : AllRealCaptures()) {
    fptn::protocol::https::obfuscator::TlsObfuscator2 writer;
    const auto frame = writer.Obfuscate(payload.data(), payload.size());
    ASSERT_TRUE(frame.has_value()) << c.host;

    const std::size_t first = FirstCompleteAt(c.flight);
    ASSERT_NE(first, 0U) << c.host;
    const std::size_t leftover = c.flight.size() - first;

    fptn::protocol::https::obfuscator::TlsObfuscator2 reader;
    if (leftover > 0) {
      reader.AddData(c.flight.data() + first, leftover);
    }
    reader.AddData(frame->data(), frame->size());

    const auto decoded = reader.Deobfuscate();
    ASSERT_TRUE(decoded.has_value())
        << c.host << ": lost the frame behind " << leftover
        << " leftover decoy bytes";
    EXPECT_EQ(decoded.value(), payload) << c.host;
  }
}

TEST(RealityResyncTest, ObfuscatorSkipsAnArbitraryTruncationPoint) {
  const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};

  for (const auto& c : AllRealCaptures()) {
    for (std::size_t cut = 0; cut < c.flight.size(); cut += 97) {
      fptn::protocol::https::obfuscator::TlsObfuscator2 writer;
      const auto frame = writer.Obfuscate(payload.data(), payload.size());
      ASSERT_TRUE(frame.has_value());

      fptn::protocol::https::obfuscator::TlsObfuscator2 reader;
      reader.AddData(c.flight.data() + cut, c.flight.size() - cut);
      reader.AddData(frame->data(), frame->size());

      const auto decoded = reader.Deobfuscate();
      ASSERT_TRUE(decoded.has_value())
          << c.host << ": lost the frame after a cut at " << cut;
      EXPECT_EQ(decoded.value(), payload) << c.host << " cut=" << cut;
    }
  }
}

TEST(RealitySessionIdTest, GeneratedDecoyIdIsAcceptedByTheServerCheck) {
  for (int i = 0; i < 200; ++i) {
    const auto sid = fptn::protocol::https::utils::GenerateDecoyTlsSessionId2();
    ASSERT_TRUE(sid.has_value());
    EXPECT_TRUE(fptn::protocol::https::utils::IsDecoyHandshakeSessionID2(
        sid->data(), sid->size()))
        << "iteration " << i;
  }
}

TEST(RealitySessionIdTest, AcceptedOnlyInsideTheClockSkewWindow) {
  const auto now = fptn::time::TimeProvider::Instance()->NowTimestamp();

  const auto build = [&](std::int64_t delta) {
    std::array<std::uint8_t, 32> sid{};
    const std::string key = fptn::protocol::https::utils::GenerateFptnKey(
        static_cast<std::uint32_t>(now + delta));
    std::memcpy(sid.data() + 14, key.data(), key.size());
    return sid;
  };

  for (const std::int64_t inside : {0, 60, -60, 119, -119}) {
    const auto sid = build(inside);
    EXPECT_TRUE(fptn::protocol::https::utils::IsDecoyHandshakeSessionID2(
        sid.data(), sid.size()))
        << "clock skew " << inside << "s must be tolerated";
  }
  for (const std::int64_t outside : {300, -300, 3600, -3600}) {
    const auto sid = build(outside);
    EXPECT_FALSE(fptn::protocol::https::utils::IsDecoyHandshakeSessionID2(
        sid.data(), sid.size()))
        << "clock skew " << outside << "s must be rejected";
  }
}

TEST(RealityObfuscatorDetectionTest, RealClientHelloIsNeverMistakenForAFrame) {
  for (const auto& c : AllRealCaptures()) {
    EXPECT_EQ(fptn::protocol::https::obfuscator::DetectObfuscator(
                  c.client_hello.data(), c.client_hello.size()),
        nullptr)
        << c.host << ": ClientHello detected as an obfuscated stream, which "
                     "makes the server skip Reality entirely";
    for (std::size_t n = 6; n < c.client_hello.size(); n += 13) {
      EXPECT_EQ(fptn::protocol::https::obfuscator::DetectObfuscator(
                    c.client_hello.data(), n),
          nullptr)
          << c.host << " truncated to " << n << " bytes";
    }
  }
}

TEST(RealityObfuscatorDetectionTest, RealServerFlightIsNeverMistakenForAFrame) {
  for (const auto& c : AllRealCaptures()) {
    fptn::protocol::https::obfuscator::TlsObfuscator2 obfuscator;
    for (const auto& r : SplitRecords(c.flight)) {
      EXPECT_FALSE(obfuscator.CheckProtocol(
          c.flight.data() + r.offset, r.total_len))
          << c.host << ": TLS record at " << r.offset
          << " accepted as an obfuscator frame";
    }
  }
}

TEST(RealityChangeCipherSpecTest, IsTheExactSixByteRecordTheServerExpects) {
  const auto ccs = fptn::protocol::https::utils::MakeClientChangeCipherSpec();
  const std::vector<std::uint8_t> expected = {
      0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
  EXPECT_EQ(ccs, expected);
}

TEST(RealityServerHelloTest, EchoesTheClientSessionIdOnEveryRealServer) {
  for (const auto& c : AllRealCaptures()) {
    const auto client_sid =
        GetTlsSessionId(c.client_hello.data(), c.client_hello.size());
    const auto server_sid = GetTlsSessionId(c.flight.data(), c.flight.size());
    ASSERT_EQ(client_sid.size(), 32U) << c.host;
    ASSERT_EQ(server_sid.size(), 32U) << c.host;
    EXPECT_EQ(client_sid, server_sid)
        << c.host << ": a real server always echoes legacy_session_id, so a "
                     "replayed ServerHello that does not is detectable";
  }
}

TEST(RealityServerHelloTest, RestampedSessionIdMatchesTheClientAgain) {
  for (const auto& c : AllRealCaptures()) {
    std::vector<std::uint8_t> replayed = c.flight;
    const std::vector<std::uint8_t> other_client_id(32, 0xAB);

    ASSERT_TRUE(
        fptn::common::network::SetTlsSessionId(replayed, other_client_id))
        << c.host;
    EXPECT_EQ(GetTlsSessionId(replayed.data(), replayed.size()),
        other_client_id)
        << c.host;
    EXPECT_EQ(replayed.size(), c.flight.size()) << c.host;

    const auto original = GetTlsSessionId(c.flight.data(), c.flight.size());
    ASSERT_TRUE(fptn::common::network::SetTlsSessionId(replayed, original));
    EXPECT_EQ(replayed, c.flight) << c.host << ": restamping is not reversible";
  }
}

TEST(RealityServerHelloTest, RestampRejectsBuffersItCannotCarry) {
  const std::vector<std::uint8_t> sid(32, 0x11);
  std::vector<std::uint8_t> tiny(10, 0x00);
  EXPECT_FALSE(fptn::common::network::SetTlsSessionId(tiny, sid));

  std::vector<std::uint8_t> empty;
  EXPECT_FALSE(fptn::common::network::SetTlsSessionId(empty, sid));

  auto flight = fptn::testing::tls::AllRealCaptures().front().flight;
  EXPECT_FALSE(fptn::common::network::SetTlsSessionId(flight, {}));
  EXPECT_FALSE(
      fptn::common::network::SetTlsSessionId(flight, std::vector<uint8_t>(8)));
}
