/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ipv6_generator.h"
#include "common/network/ipv6_utils.h"

// This test demonstrates that the IPv6 string representation from the
// generator must match the format produced by
// fptn::common::network::IPv6Address::toString(), because the server NAT table
// uses these strings as map keys. If the formats differ, the NAT lookup fails
// and IPv6 response packets are silently dropped.
TEST(IPv6UtilsTest, ToStringMatchesPcppFormat) {
  // Simulate what the IPv6 generator does: convert an address to uint128,
  // then back to string using ipv6::toString()
  const std::string original = "fc00:1::2";
  const auto boost_addr = boost::asio::ip::make_address_v6(original);
  const auto uint128_val = fptn::common::network::ipv6::toUInt128(boost_addr);
  const std::string generator_str =
      fptn::common::network::ipv6::toString(uint128_val);

  // Simulate what happens when a response packet arrives: pcpp extracts
  // the IPv6 address and we call toString() on it
  const fptn::common::network::IPv6Address pcpp_addr(original);
  const std::string& pcpp_str = pcpp_addr.ToString();

  // These MUST match, otherwise the NAT table lookup will fail
  EXPECT_EQ(generator_str, pcpp_str)
      << "IPv6 string format mismatch between generator ('" << generator_str
      << "') and pcpp ('" << pcpp_str
      << "'). This causes NAT table lookups to fail, "
         "dropping all IPv6 response packets.";
}

// Test with the actual server default subnet
TEST(IPv6UtilsTest, ServerDefaultSubnetMatchesPcpp) {
  // Server defaults from CMakeLists.txt:
  //   FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6="fc00:1::"
  //   Mask: /112
  fptn::common::network::IPv6AddressGenerator generator(
      fptn::common::network::IPv6Address("fc00:1::"), 112);

  // Generate a few addresses and verify they match pcpp's format
  for (int i = 1; i <= 5; i++) {
    const auto generated = generator.GetNextAddress();
    const auto& gen_str = generated.ToString();

    // Round-trip through pcpp (simulates what happens on packet receive)
    const fptn::common::network::IPv6Address pcpp_addr(gen_str);
    const std::string& pcpp_str = pcpp_addr.ToString();

    EXPECT_EQ(gen_str, pcpp_str)
        << "Mismatch for generated address #" << i << ": generator='" << gen_str
        << "' vs pcpp='" << pcpp_str << "'";
  }
}

// Test with various address patterns that exercise zero-compression
TEST(IPv6UtilsTest, ToStringFormatsMatchPcppForVariousAddresses) {
  const std::vector<std::string> test_addresses = {
      "::1",
      "fe80::1",
      "2001:db8::1",
      "fc00:1::2",
      "2001:db8:85a3::8a2e:370:7334",
      "ff02::1",
      "::",
  };

  for (const auto& addr_str : test_addresses) {
    const auto boost_addr = boost::asio::ip::make_address_v6(addr_str);
    const auto uint128_val = fptn::common::network::ipv6::toUInt128(boost_addr);
    const std::string utils_str =
        fptn::common::network::ipv6::toString(uint128_val);

    const fptn::common::network::IPv6Address pcpp_addr(addr_str);
    const std::string& pcpp_str = pcpp_addr.ToString();

    EXPECT_EQ(utils_str, pcpp_str)
        << "Format mismatch for input '" << addr_str << "': utils='"
        << utils_str << "' vs pcpp='" << pcpp_str << "'";
  }
}
