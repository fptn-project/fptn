/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

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

  explicit IPAddress(const std::string& ip) : ip_(ip) {
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

  bool IsEmpty() const { return ip_.empty() || ip_impl_ == T(); }

  bool IsValid() const { return !ip_.empty() && ip_impl_ != T(); }

  const std::string& ToString() const { return ip_; }

  // Add copy and move constructors/assignment for base class
  IPAddress(const IPAddress& other)
      : ip_(other.ip_), ip_impl_(other.ip_impl_) {}

  IPAddress(IPAddress&& other) noexcept
      : ip_(std::move(other.ip_)), ip_impl_(std::move(other.ip_impl_)) {}

  IPAddress& operator=(const IPAddress& other) {
    if (this != &other) {
      ip_ = other.ip_;
      ip_impl_ = other.ip_impl_;
    }
    return *this;
  }

  IPAddress& operator=(IPAddress&& other) noexcept {
    if (this != &other) {
      ip_ = std::move(other.ip_);
      ip_impl_ = std::move(other.ip_impl_);
    }
    return *this;
  }

  bool operator!=(const IPAddress<T>& other) const noexcept {
    return ip_ != other.ip_ || ip_impl_ != other.ip_impl_;
  }

  bool operator==(const IPAddress<T>& other) const noexcept {
    return ip_ == other.ip_ && ip_impl_ == other.ip_impl_;
  }

  std::uint32_t ToInt() const {
    if (ip_impl_.is_v4()) {
      return ip_impl_.to_v4().to_uint();
    }
    return 0;  // For IPv6, return 0 or handle differently
  }

 protected:
  std::string ip_;
  T ip_impl_;
};

class IPv4Address : public IPAddress<boost::asio::ip::address> {
 public:
  // Default constructor
  IPv4Address() = default;

  // Constructor from string
  explicit IPv4Address(const std::string& ip)
      : IPAddress<boost::asio::ip::address>(ip) {
    // Additional validation for IPv4
    if (!ip_.empty() && !ip_impl_.is_v4()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  // Constructor from boost::asio::ip::address object
  explicit IPv4Address(const boost::asio::ip::address& ip_addr)
      : IPAddress<boost::asio::ip::address>(ip_addr.to_string()) {
    if (!ip_addr.is_v4()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  // Copy constructor
  IPv4Address(const IPv4Address& other)
      : IPAddress<boost::asio::ip::address>(other) {}

  // Move constructor
  IPv4Address(IPv4Address&& other) noexcept
      : IPAddress<boost::asio::ip::address>(std::move(other)) {}

  // Copy assignment operator
  IPv4Address& operator=(const IPv4Address& other) {
    if (this != &other) {
      IPAddress<boost::asio::ip::address>::operator=(other);
    }
    return *this;
  }

  // Move assignment operator
  IPv4Address& operator=(IPv4Address&& other) noexcept {
    if (this != &other) {
      IPAddress<boost::asio::ip::address>::operator=(std::move(other));
    }
    return *this;
  }

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

  virtual std::uint32_t ToInt() const {
    if (ip_impl_.is_v4()) {
      return ip_impl_.to_v4().to_uint();
    }
    return 0;
  }
};

class IPv6Address : public IPAddress<boost::asio::ip::address> {
 public:
  // Default constructor
  IPv6Address() = default;

  // Constructor from string
  explicit IPv6Address(const std::string& ip)
      : IPAddress<boost::asio::ip::address>(ip) {
    // Additional validation for IPv6
    if (!ip_.empty() && !ip_impl_.is_v6()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  // Constructor from boost::asio::ip::address object
  explicit IPv6Address(const boost::asio::ip::address& ip_addr)
      : IPAddress<boost::asio::ip::address>(ip_addr.to_string()) {
    if (!ip_addr.is_v6()) {
      ip_impl_ = boost::asio::ip::address();
    }
  }

  // Copy constructor
  IPv6Address(const IPv6Address& other)
      : IPAddress<boost::asio::ip::address>(other) {}

  // Move constructor
  IPv6Address(IPv6Address&& other) noexcept
      : IPAddress<boost::asio::ip::address>(std::move(other)) {}

  // Copy assignment operator
  IPv6Address& operator=(const IPv6Address& other) {
    if (this != &other) {
      IPAddress<boost::asio::ip::address>::operator=(other);
    }
    return *this;
  }

  // Move assignment operator
  IPv6Address& operator=(IPv6Address&& other) noexcept {
    if (this != &other) {
      IPAddress<boost::asio::ip::address>::operator=(std::move(other));
    }
    return *this;
  }

  static IPv6Address Create(const std::string& ip) { return IPv6Address(ip); }

  static IPv6Address Create(const boost::asio::ip::address& ip_addr) {
    return IPv6Address(ip_addr);
  }

  static IPv6Address Create(const IPv6Address& ip_addr) {
    return IPv6Address(ip_addr);
  }

  // Additional IPv6-specific methods
  virtual bool IsValid() const {
    return IPAddress<boost::asio::ip::address>::IsValid() && ip_impl_.is_v6();
  }
};

}  // namespace fptn::common::network
