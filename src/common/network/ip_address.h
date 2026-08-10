/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include <boost/asio/ip/address.hpp>

namespace fptn::common::network {

template <class T>
class IPAddress {
 public:
  IPAddress() = default;
  virtual ~IPAddress() = default;
  explicit IPAddress(const std::string& ip) {
    if (!ip.empty()) {
      try {
        ip_impl_ = boost::asio::ip::make_address(ip);
      } catch (const boost::system::system_error&) {
        // Invalid address, leave ip_impl_ as default constructed
        ip_impl_ = T();
      }
    }
  }

  T Get() const noexcept { return ip_impl_; }

  bool IsEmpty() const { return ip_impl_ == T(); }

  bool IsValid() const { return ip_impl_ != T(); }

  std::string ToString() const { return ip_impl_.to_string(); }

  IPAddress(const IPAddress& other) = default;
  IPAddress(IPAddress&& other) noexcept = default;
  IPAddress& operator=(const IPAddress& other) = default;
  IPAddress& operator=(IPAddress&& other) noexcept = default;

  bool operator!=(const IPAddress<T>& other) const noexcept {
    return ip_impl_ != other.ip_impl_;
  }

  bool operator==(const IPAddress<T>& other) const noexcept {
    return ip_impl_ == other.ip_impl_;
  }

  std::uint32_t ToInt() const {
    if (ip_impl_.is_v4()) {
      return ip_impl_.to_v4().to_uint();
    }
    return 0;  // For IPv6, return 0 or handle differently
  }

 protected:
  explicit IPAddress(T ip_impl) : ip_impl_(std::move(ip_impl)) {}

  T ip_impl_;
};

class IPv4Address : public IPAddress<boost::asio::ip::address> {
 public:
  // Default constructor
  IPv4Address() = default;

  // Constructor from string
  explicit IPv4Address(const std::string& ip)
      : IPAddress<boost::asio::ip::address>(ip) {
    if (!ip_impl_.is_v4()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  explicit IPv4Address(std::uint32_t addr)
      : IPAddress<boost::asio::ip::address>(boost::asio::ip::address_v4(addr)) {
  }

  // Constructor from boost::asio::ip::address object
  explicit IPv4Address(const boost::asio::ip::address& ip_addr)
      : IPAddress<boost::asio::ip::address>(
            ip_addr.is_v4() ? ip_addr : boost::asio::ip::address()) {}

  IPv4Address(const IPv4Address& other) = default;
  IPv4Address(IPv4Address&& other) noexcept = default;
  IPv4Address& operator=(const IPv4Address& other) = default;
  IPv4Address& operator=(IPv4Address&& other) noexcept = default;

  static IPv4Address Create(const std::string& ip) { return IPv4Address(ip); }

  static IPv4Address Create(const boost::asio::ip::address& ip_addr) {
    return IPv4Address(ip_addr);
  }

  static IPv4Address Create(const IPv4Address& ip_addr) {
    return IPv4Address(ip_addr);
  }

  // Additional IPv4-specific methods
  virtual bool IsValid() const {
    return IPAddress<boost::asio::ip::address>::IsValid() && ip_impl_.is_v4();
  }

  virtual std::uint32_t ToInt() const noexcept {
    try {
      if (ip_impl_.is_v4()) {
        return ip_impl_.to_v4().to_uint();
      }
    } catch (...) {
    }
    return 0;
  }
};

class IPv6Address : public IPAddress<boost::asio::ip::address> {
 public:
  using Bytes = std::array<std::uint8_t, 16>;

  // Default constructor
  IPv6Address() = default;

  // Constructor from string
  explicit IPv6Address(const std::string& ip)
      : IPAddress<boost::asio::ip::address>(ip) {
    // Additional validation for IPv6
    if (!ip_impl_.is_v6()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  // Constructor from the raw 16 bytes
  explicit IPv6Address(const Bytes& addr)
      : IPAddress<boost::asio::ip::address>(boost::asio::ip::address_v6(addr)) {
  }

  // Constructor from boost::asio::ip::address object
  explicit IPv6Address(const boost::asio::ip::address& ip_addr)
      : IPAddress<boost::asio::ip::address>(
            ip_addr.is_v6() ? ip_addr : boost::asio::ip::address()) {}

  IPv6Address(const IPv6Address& other) = default;
  IPv6Address(IPv6Address&& other) noexcept = default;
  IPv6Address& operator=(const IPv6Address& other) = default;
  IPv6Address& operator=(IPv6Address&& other) noexcept = default;

  static IPv6Address Create(const std::string& ip) { return IPv6Address(ip); }

  static IPv6Address Create(const boost::asio::ip::address& ip_addr) {
    return IPv6Address(ip_addr);
  }

  static IPv6Address Create(const IPv6Address& ip_addr) {
    return IPv6Address(ip_addr);
  }

  // Raw address bytes
  Bytes ToBytes() const noexcept {
    if (!ip_impl_.is_v6()) {
      return Bytes{};
    }
    return ip_impl_.to_v6().to_bytes();
  }

  // Additional IPv6-specific methods
  virtual bool IsValid() const {
    return IPAddress<boost::asio::ip::address>::IsValid() && ip_impl_.is_v6();
  }
};

}  // namespace fptn::common::network
