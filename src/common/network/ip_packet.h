/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "common/utils/utils.h"

#if _WIN32
#pragma warning(disable : 4996)
#endif

#if _WIN32
#include <Winsock2.h>  // NOLINT(build/include_order)

#include <openssl/base.h>  // NOLINT(build/include_order)
#else
#include <arpa/inet.h>
#endif

#include <iostream>

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
#include "common/network/ip_address.h"
#else

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <pcapplusplus/ArpLayer.h>     // NOLINT(build/include_order)
#include <pcapplusplus/EthLayer.h>     // NOLINT(build/include_order)
#include <pcapplusplus/IPv4Layer.h>    // NOLINT(build/include_order)
#include <pcapplusplus/IPv6Layer.h>    // NOLINT(build/include_order)
#include <pcapplusplus/IcmpLayer.h>    // NOLINT(build/include_order)
#include <pcapplusplus/IcmpV6Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/MacAddress.h>   // NOLINT(build/include_order)
#include <pcapplusplus/Packet.h>       // NOLINT(build/include_order)

#ifdef TCPOPT_CC
#undef TCPOPT_CC
#endif  // TCPOPT_CC
#ifdef TCPOPT_CCNEW
#undef TCPOPT_CCNEW
#endif  // TCPOPT_CCNEW
#ifdef TCPOPT_CCECHO
#undef TCPOPT_CCECHO
#endif  // TCPOPT_CCECHO

#include <pcapplusplus/DnsLayer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/TcpLayer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/UdpLayer.h>  // NOLINT(build/include_order)

#if _WIN32
#pragma warning(default : 4996)
#endif

#endif

#ifdef FPTN_WITH_LIBIDN2
#include <idn2.h>
#endif

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/client_id.h"
#include "common/network/ip_address.h"

namespace fptn::common::network {

#define FPTN_PACKET_UNDEFINED_CLIENT_ID MAX_CLIENT_ID

#ifndef FPTN_IP_ADDRESS_WITHOUT_PCAP

using IPPacketData = std::vector<std::uint8_t>;

inline bool CheckIPv4(const IPPacketData& buffer) {
  return (static_cast<std::uint8_t>(buffer[0]) >> 4) == 4;
}

inline bool CheckIPv6(const IPPacketData& buffer) {
  return (static_cast<std::uint8_t>(buffer[0]) >> 4) == 6;
}

#ifdef FPTN_WITH_LIBIDN2

inline bool IsPunycode(const std::string& str) {
  return str.find("xn--") != std::string::npos;
}

inline std::string ConvertDomainToUnicode(const std::string& domain) {
  if (domain.empty()) {
    return domain;
  }

  char* result = nullptr;
  const int ret = idn2_to_unicode_8z8z(domain.c_str(), &result, 0);

  if (ret == IDN2_OK && result != nullptr) {
    std::string unicode_result = result;
    free(result);
    return unicode_result;
  }
  if (result != nullptr) {
    free(result);
  }
  return domain;
}
#endif

class IPPacket {
 public:
  static std::unique_ptr<IPPacket> Parse(IPPacketData buffer,
      fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    // Minimum IPv4 header size
    if (buffer.empty() || buffer.size() < 20) {
      return nullptr;
    }
    if (CheckIPv4(buffer)) {
      auto packet = std::make_unique<IPPacket>(
          std::move(buffer), client_id, pcpp::LINKTYPE_IPV4);
      if (nullptr != packet->IPv4Layer()) {
        return packet;
      }
    } else if (CheckIPv6(buffer)) {
      auto packet = std::make_unique<IPPacket>(
          std::move(buffer), client_id, pcpp::LINKTYPE_IPV6);
      if (nullptr != packet->IPv6Layer()) {
        return packet;
      }
    }
    return nullptr;
  }

 public:
  IPPacket(IPPacketData data,
      fptn::ClientID client_id,
      const pcpp::LinkLayerType& ip_type)
      : packet_data_(std::move(data)), client_id_(client_id) {
    try {
      raw_packet_ = pcpp::RawPacket(
          reinterpret_cast<const uint8_t*>(packet_data_.data()),
          static_cast<int>(packet_data_.size()), timeval{0, 0}, false, ip_type);

      parsed_packet_ = pcpp::Packet(&raw_packet_, false);
      if (pcpp::LINKTYPE_IPV4 == ip_type) {
        ipv4_layer_ = parsed_packet_.getLayerOfType<pcpp::IPv4Layer>();
      } else if (pcpp::LINKTYPE_IPV6 == ip_type) {
        ipv6_layer_ = parsed_packet_.getLayerOfType<pcpp::IPv6Layer>();
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN(
          "IP Packet parsing exception (client {}): {}", client_id_, e.what());
    } catch (...) {
      SPDLOG_WARN("Unknown error while parsing IP Packet");
    }
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  void ComputeCalculateFields() noexcept {
    auto* tcp_layer = parsed_packet_.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer) {
      tcp_layer->computeCalculateFields();
    } else {
      auto* udp_layer = parsed_packet_.getLayerOfType<pcpp::UdpLayer>();
      if (udp_layer) {
        udp_layer->computeCalculateFields();
      }
    }
    if (ipv4_layer_) {
      ipv4_layer_->computeCalculateFields();
    } else if (ipv6_layer_) {
      auto* icmp_layer = parsed_packet_.getLayerOfType<pcpp::IcmpV6Layer>();
      if (icmp_layer) {
        icmp_layer->computeCalculateFields();
      }
      ipv6_layer_->computeCalculateFields();
    }
  }

  void SetClientId(fptn::ClientID client_id) noexcept {
    client_id_ = client_id;
  }

  void SetDstIPv4Address(const pcpp::IPv4Address& dst) noexcept {
    if (ipv4_layer_) {
      ipv4_layer_->getIPv4Header()->timeToLive -= 1;
      ipv4_layer_->setDstIPv4Address(dst);
    }
  }

  void SetSrcIPv4Address(const pcpp::IPv4Address& src) noexcept {
    if (ipv4_layer_) {
      ipv4_layer_->getIPv4Header()->timeToLive -= 1;
      ipv4_layer_->setSrcIPv4Address(src);
    }
  }

  void SetDstIPv6Address(const pcpp::IPv6Address& dst) noexcept {
    if (ipv6_layer_) {
      ipv6_layer_->setDstIPv6Address(dst);
    }
  }

  void SetSrcIPv6Address(const pcpp::IPv6Address& src) noexcept {
    if (ipv6_layer_) {
      ipv6_layer_->setSrcIPv6Address(src);
    }
  }

  bool IsICMPv4() const {
    const auto* icmp_v4 = parsed_packet_.getLayerOfType<pcpp::IcmpLayer>();
    return icmp_v4 != nullptr;
  }

  bool IsICMPv6() const {
    const auto* icmp_v6 = parsed_packet_.getLayerOfType<pcpp::IcmpV6Layer>();
    return icmp_v6 != nullptr;
  }

  bool IsDns() const {
    const auto* udp = parsed_packet_.getLayerOfType<pcpp::UdpLayer>();
    if (udp && (udp->getDstPort() == 53 || udp->getSrcPort() == 53)) {
      return GetDnsLayer() != nullptr;
    }

    const auto* tcp = parsed_packet_.getLayerOfType<pcpp::TcpLayer>();
    if (tcp && (tcp->getDstPort() == 53 || tcp->getSrcPort() == 53)) {
      return GetDnsLayer() != nullptr;
    }
    return false;
  }

  std::optional<std::string> GetDnsDomain() const {
    const auto* dns_layer = GetDnsLayer();
    if (dns_layer) {
      const auto* query = dns_layer->getFirstQuery();
      if (query) {
        std::string domain_name = query->getName();
#ifdef FPTN_WITH_LIBIDN2
        if (IsPunycode(domain_name)) {
          return ConvertDomainToUnicode(domain_name);
        }
#endif
        return domain_name;
      }
    }
    return std::nullopt;
  }

  std::vector<fptn::common::network::IPv4Address> GetDnsIPv4Addresses() const {
    const auto* dns_layer = GetDnsLayer();
    if (!dns_layer) {
      return {};
    }

    if (dns_layer->getDnsHeader()->queryOrResponse != 1) {
      return {};
    }

    std::vector<fptn::common::network::IPv4Address> ipv4_addresses;
    auto* answer = dns_layer->getFirstAnswer();

    while (answer != nullptr) {
      if (answer->getDnsType() == pcpp::DNS_TYPE_A) {
        try {
          const std::size_t data_offset = answer->getDataOffset();
          const std::size_t data_length = answer->getDataLength();
          if (data_length == 4) {
            const std::uint8_t* dns_raw_data = dns_layer->getData();
            const std::size_t dns_data_len = dns_layer->getDataLen();

            if (data_offset + 4 <= dns_data_len) {
              const uint8_t* ip_bytes = dns_raw_data + data_offset;
              const std::uint32_t ip_int =
                  (static_cast<uint32_t>(ip_bytes[0]) << 24) |
                  (static_cast<uint32_t>(ip_bytes[1]) << 16) |
                  (static_cast<uint32_t>(ip_bytes[2]) << 8) |
                  static_cast<uint32_t>(ip_bytes[3]);

              const auto addr = boost::asio::ip::make_address_v4(ip_int);
              ipv4_addresses.emplace_back(addr.to_string());
            }
          }
        } catch (const std::exception& e) {
          SPDLOG_WARN("Failed to parse IPv4 from DNS answer '{}': {}",
              answer->getName(), e.what());
        }
      }
      answer = dns_layer->getNextAnswer(answer);
    }
    return ipv4_addresses;
  }

  std::vector<fptn::common::network::IPv6Address> GetDnsIPv6Addresses() const {
    const auto* dns_layer = GetDnsLayer();
    if (!dns_layer) {
      return {};
    }

    if (dns_layer->getDnsHeader()->queryOrResponse != 1) {
      return {};
    }

    std::vector<fptn::common::network::IPv6Address> ipv6_addresses;
    auto* answer = dns_layer->getFirstAnswer();

    while (answer != nullptr) {
      if (answer->getDnsType() == pcpp::DNS_TYPE_AAAA) {
        try {
          const std::size_t data_offset = answer->getDataOffset();
          const std::size_t data_length = answer->getDataLength();

          if (data_length == 16) {
            const std::uint8_t* dns_raw_data = dns_layer->getData();
            const std::size_t dns_data_len = dns_layer->getDataLen();

            if (data_offset + 16 <= dns_data_len) {
              const uint8_t* ip_bytes = dns_raw_data + data_offset;
              std::array<unsigned char, 16> bytes;
              std::memcpy(bytes.data(), ip_bytes, 16);

              const auto addr = boost::asio::ip::make_address_v6(bytes);
              ipv6_addresses.emplace_back(addr.to_string());
            }
          }
        } catch (const std::exception& e) {
          SPDLOG_WARN("Failed to parse IPv6 from DNS answer '{}': {}",
              answer->getName(), e.what());
        }
      }
      answer = dns_layer->getNextAnswer(answer);
    }
    return ipv6_addresses;
  }

  fptn::ClientID ClientId() const noexcept { return client_id_; }

  pcpp::Packet& Pkt() noexcept { return parsed_packet_; }

  std::size_t Size() const noexcept { return packet_data_.size(); }

  const pcpp::RawPacket* GetRawPacket() const noexcept {
    return parsed_packet_.getRawPacket();
  }

 protected:
  pcpp::DnsLayer* GetDnsLayer() const {
    try {
      auto* udp_layer = parsed_packet_.getLayerOfType<pcpp::UdpLayer>();
      if (udp_layer) {
        return parsed_packet_.getLayerOfType<pcpp::DnsLayer>();
      }
      auto* tcp_layer = parsed_packet_.getLayerOfType<pcpp::TcpLayer>();
      if (tcp_layer && tcp_layer->getLayerPayloadSize() >= 2) {
        return parsed_packet_.getLayerOfType<pcpp::DnsLayer>();
      }
    } catch (...) {
      // ignore
    }
    return nullptr;
  }

 public:
  // TODO(stas): Remove virtual functions in the future for better performance.
  // TODO(stas): Anti-scan tests are currently inadequate and need improvement.
  virtual ~IPPacket() = default;
  virtual bool IsIPv4() const noexcept { return ipv4_layer_ != nullptr; }
  virtual bool IsIPv6() const noexcept { return ipv6_layer_ != nullptr; }
  virtual pcpp::IPv4Layer* IPv4Layer() noexcept { return ipv4_layer_; }
  virtual pcpp::IPv6Layer* IPv6Layer() noexcept { return ipv6_layer_; }

 protected:
  // for tests only
  IPPacket() : client_id_(FPTN_PACKET_UNDEFINED_CLIENT_ID) {}

 private:
  std::vector<std::uint8_t> packet_data_;
  fptn::ClientID client_id_;
  pcpp::RawPacket raw_packet_;
  pcpp::Packet parsed_packet_;

  pcpp::IPv4Layer* ipv4_layer_ = nullptr;
  pcpp::IPv6Layer* ipv6_layer_ = nullptr;
};

using IPPacketPtr = std::unique_ptr<IPPacket>;

#else

/**
 * Specific lightweight container for IPv4 packets.
 * Wraps raw IP packet data with basic access methods.
 */
class LightIPv4Packet {
 public:
  static std::unique_ptr<LightIPv4Packet> Parse(IPPacketData buffer,
      std::uint64_t client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    if (buffer.empty() || buffer.size() < 20) {  // Minimum IPv4 header size
      return nullptr;
    }
    return std::make_unique<LightIPv4Packet>(std::move(buffer), client_id);
  }

  LightIPv4Packet(IPPacketData buffer, const fptn::ClientID client_id)
      : ip_packet_(std::move(buffer)) {
    (void)client_id;
  }

  std::size_t Size() const { return ip_packet_.size(); }

  // specific methods to have general interface with IPPacket
  const LightIPv4Packet* GetRawPacket() const { return this; }
  std::size_t getRawDataLen() const { return ip_packet_.size(); }
  const void* getRawData() const { return ip_packet_.data(); }

 private:
  const IPPacketData ip_packet_;
};

using IPPacket = LightIPv4Packet;
using IPPacketPtr = std::unique_ptr<LightIPv4Packet>;

#endif

}  // namespace fptn::common::network
