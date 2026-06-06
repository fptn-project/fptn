/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace fptn::common::network::ipv6 {
inline boost::multiprecision::uint128_t toUInt128(
    const boost::asio::ip::address_v6& address) {
  boost::multiprecision::uint128_t result{};
  for (uint8_t b : address.to_bytes()) {
    (result <<= 8) |= b;
  }
  return result;
}

inline boost::multiprecision::uint128_t toUInt128(
    const fptn::common::network::IPv6Address& address) {
  return toUInt128(boost::asio::ip::make_address_v6(address.ToString()));
}

inline std::string toString(const boost::multiprecision::uint128_t& val) {
  const std::uint64_t high = static_cast<uint64_t>(val >> 64);  // High 64 bits
  const std::uint64_t low = static_cast<uint64_t>(val & 0xFFFFFFFFFFFFFFFF);
  // Build 16-byte network-order address from the two 64-bit halves
  const boost::asio::ip::address_v6::bytes_type bytes = {{
      static_cast<unsigned char>(high >> 56),
      static_cast<unsigned char>(high >> 48),
      static_cast<unsigned char>(high >> 40),
      static_cast<unsigned char>(high >> 32),
      static_cast<unsigned char>(high >> 24),
      static_cast<unsigned char>(high >> 16),
      static_cast<unsigned char>(high >> 8),
      static_cast<unsigned char>(high),
      static_cast<unsigned char>(low >> 56),
      static_cast<unsigned char>(low >> 48),
      static_cast<unsigned char>(low >> 40),
      static_cast<unsigned char>(low >> 32),
      static_cast<unsigned char>(low >> 24),
      static_cast<unsigned char>(low >> 16),
      static_cast<unsigned char>(low >> 8),
      static_cast<unsigned char>(low),
  }};
  // Produces canonical compressed format (matches pcpp/inet_ntop)
  return boost::asio::ip::make_address_v6(bytes).to_string();
}
}  // namespace fptn::common::network::ipv6
