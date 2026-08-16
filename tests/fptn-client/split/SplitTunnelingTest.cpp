/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "plugins/split/tunneling.h"

// Routes are not touched by the matcher, so the test links these stubs instead
// of route_manager.cpp with its platform-specific TUN headers.
namespace fptn::routing {

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
bool RouteManager::AddDnsRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>&, RoutingPolicy) {
  return true;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
bool RouteManager::AddDnsRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>&, RoutingPolicy) {
  return true;
}

}  // namespace fptn::routing

namespace {

fptn::plugin::Tunneling MakeTunneling(const std::vector<std::string>& rules) {
  return fptn::plugin::Tunneling(
      rules, nullptr, fptn::routing::RoutingPolicy::kExcludeFromVpn);
}

fptn::plugin::Tunneling MakeDefaultTunneling() {
  return MakeTunneling({"ru", "su", "рф", "xn--p1ai", "vk.com"});
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(SplitTunnelingTest, MatchesTopLevelDomainRule) {
  const auto tunneling = MakeDefaultTunneling();

  EXPECT_TRUE(tunneling.IsMatched("ru"));
  EXPECT_TRUE(tunneling.IsMatched("mail.ru"));
  EXPECT_TRUE(tunneling.IsMatched("gosuslugi.ru"));
  EXPECT_TRUE(tunneling.IsMatched("api.some.sub.gosuslugi.ru"));
  EXPECT_TRUE(tunneling.IsMatched("example.su"));
}

TEST(SplitTunnelingTest, MatchesCyrillicAndPunycodeTld) {
  const auto tunneling = MakeDefaultTunneling();

  EXPECT_TRUE(tunneling.IsMatched("рф"));
  EXPECT_TRUE(tunneling.IsMatched("сайт.рф"));
  EXPECT_TRUE(tunneling.IsMatched("почта.сайт.рф"));
  EXPECT_TRUE(tunneling.IsMatched("xn--p1ai"));
  EXPECT_TRUE(tunneling.IsMatched("xn--80aswg.xn--p1ai"));
}

TEST(SplitTunnelingTest, MatchesDomainAndItsSubdomains) {
  const auto tunneling = MakeDefaultTunneling();

  EXPECT_TRUE(tunneling.IsMatched("vk.com"));
  EXPECT_TRUE(tunneling.IsMatched("sub.vk.com"));
  EXPECT_TRUE(tunneling.IsMatched("a.b.c.vk.com"));
}

TEST(SplitTunnelingTest, DoesNotMatchUnrelatedDomains) {
  const auto tunneling = MakeDefaultTunneling();

  EXPECT_FALSE(tunneling.IsMatched("google.com"));
  EXPECT_FALSE(tunneling.IsMatched("vk.com.evil.net"));
  EXPECT_FALSE(tunneling.IsMatched("notvk.com"));
  EXPECT_FALSE(tunneling.IsMatched("ruse.com"));
  EXPECT_FALSE(tunneling.IsMatched("myru"));
  EXPECT_FALSE(tunneling.IsMatched(""));
}

TEST(SplitTunnelingTest, AcceptsLegacyAndDirtyRules) {
  const auto tunneling =
      MakeTunneling({"domain:vk.com", "  YANDEX.RU  ", "ok.ru."});

  EXPECT_TRUE(tunneling.IsMatched("vk.com"));
  EXPECT_TRUE(tunneling.IsMatched("sub.vk.com"));
  EXPECT_TRUE(tunneling.IsMatched("yandex.ru"));
  EXPECT_TRUE(tunneling.IsMatched("mail.yandex.ru"));
  EXPECT_TRUE(tunneling.IsMatched("ok.ru"));
}

TEST(SplitTunnelingTest, EmptyRulesMatchNothing) {
  const auto tunneling = MakeTunneling({});

  EXPECT_FALSE(tunneling.IsMatched("vk.com"));
  EXPECT_FALSE(tunneling.IsMatched("mail.ru"));
}
