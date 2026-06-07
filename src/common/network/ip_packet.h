/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#if _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#ifdef FPTN_WITH_LIBIDN2
#include <idn2.h>
#endif

#ifdef USING_MIMALLOC
#include <mimalloc.h>
#endif

#include <spdlog/spdlog.h>

#include "common/client_id.h"
#include "common/network/ip_address.h"
#include "common/network/ip_utils.h"
#include "common/utils/utils.h"

namespace fptn::common::network {

#ifdef USING_MIMALLOC
using IPPacketData = std::vector<std::uint8_t, mi_stl_allocator<std::uint8_t>>;
#else
using IPPacketData = std::vector<std::uint8_t>;
#endif

#define FPTN_PACKET_UNDEFINED_CLIENT_ID MAX_CLIENT_ID

namespace detail {

inline constexpr std::size_t kMinIPv4 = 20;
inline constexpr std::size_t kMinIPv6 = 40;
inline constexpr std::size_t kUdpHdr = 8;
inline constexpr std::size_t kDnsHdr = 12;

inline int Ipv4Ihl(const std::uint8_t* p) noexcept {
  return (p[0] & 0x0Fu) * 4;
}

inline std::uint8_t Ipv4Proto(const std::uint8_t* p) noexcept { return p[9]; }

inline std::uint8_t& Ipv4Ttl(std::uint8_t* p) noexcept { return p[8]; }

inline std::uint8_t Ipv6Next(const std::uint8_t* p) noexcept { return p[6]; }

inline const std::uint8_t* DnsPayloadPtr(
    const std::uint8_t* udp, const std::uint8_t* end) noexcept {
  if (udp + kUdpHdr > end) {
    return nullptr;
  }
  if (ReadU16Be(udp) != 53 && ReadU16Be(udp + 2) != 53) {
    return nullptr;
  }
  const std::uint8_t* dns = udp + kUdpHdr;
  return (dns + kDnsHdr <= end) ? dns : nullptr;
}

// Parses a DNS name at *cur with pointer-compression support (RFC 1035).
// Advances *cur past the uncompressed portion.
inline std::string ParseDnsName(const std::uint8_t* base,
    const std::uint8_t* end,
    const std::uint8_t*& cur) noexcept {
  std::string name;
  bool jumped = false;
  const std::uint8_t* ptr = cur;
  for (int i = 0; i < 128 && ptr < end; ++i) {
    const std::uint8_t len = *ptr;
    if (len == 0u) {
      if (!jumped) cur = ptr + 1;
      break;
    }
    if ((len & 0xC0u) == 0xC0u) {
      if (ptr + 2 > end) {
        break;
      }
      if (!jumped) {
        cur = ptr + 2;
      }
      jumped = true;
      ptr = base + (static_cast<std::uint16_t>(len & 0x3Fu) << 8 | ptr[1]);
      continue;
    }
    ++ptr;
    if (ptr + len > end) {
      break;
    }
    if (!name.empty()) {
      name += '.';
    }
    name.append(reinterpret_cast<const char*>(ptr), len);
    ptr += len;
  }
  return name;
}

inline const std::uint8_t* DnsAnswerStart(const std::uint8_t* dns,
    const std::uint8_t* end,
    int* out_ancount) noexcept {
  if (dns + kDnsHdr > end) {
    return nullptr;
  }
  if ((dns[2] & 0x80u) == 0u) {
    return nullptr;
  }
  const int qdcount = static_cast<int>(ReadU16Be(dns + 4));
  *out_ancount = static_cast<int>(ReadU16Be(dns + 6));
  if (*out_ancount == 0) {
    return nullptr;
  }

  const std::uint8_t* cur = dns + kDnsHdr;
  for (int q = 0; q < qdcount && cur < end; ++q) {
    for (int s = 0; s < 256 && cur < end; ++s) {
      const std::uint8_t l = *cur;
      if (l == 0u) {
        ++cur;
        break;
      }
      if ((l & 0xC0u) == 0xC0u) {
        cur += 2;
        break;
      }
      cur += 1 + l;
    }
    cur += 4;  // QTYPE + QCLASS
  }
  return (cur < end) ? cur : nullptr;
}

#ifdef FPTN_WITH_LIBIDN2
inline bool IsPunycode(const std::string& s) noexcept {
  return s.find("xn--") != std::string::npos;
}
inline std::string ToUnicode(const std::string& domain) noexcept {
  char* r = nullptr;
  if (idn2_to_unicode_8z8z(domain.c_str(), &r, 0) == IDN2_OK && r) {
    std::string out = r;
    free(r);
    return out;
  }
  if (r) free(r);
  return domain;
}
#endif

}  // namespace detail

class IPPacket {
 public:
  static std::unique_ptr<IPPacket> Parse(IPPacketData buffer,
      fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    const std::size_t sz = buffer.size();
    if (sz < detail::kMinIPv4) {
      return nullptr;
    }
    const std::uint8_t ver = buffer[0] >> 4;
    if (ver == 4 || (ver == 6 && sz >= detail::kMinIPv6)) {
      return std::make_unique<IPPacket>(std::move(buffer), client_id);
    }
    return nullptr;
  }

  static std::unique_ptr<IPPacket> Parse(
      const std::uint8_t* buf, std::size_t sz) {
    if (!buf || sz == 0) {
      return nullptr;
    }
    IPPacketData packet(buf, buf + sz);
    return Parse(std::move(packet));
  }

  IPPacket(IPPacketData data, fptn::ClientID client_id)
      : data_(std::move(data)), client_id_(client_id) {}

  virtual ~IPPacket() = default;

  void ComputeCalculateFields() noexcept {
    if (data_.size() < detail::kMinIPv4) {
      return;
    }
    RecalculateChecksums(data_.data(), data_.size());
  }

  fptn::ClientID ClientId() const noexcept { return client_id_; }
  void SetClientId(fptn::ClientID id) noexcept { client_id_ = id; }

  virtual bool IsIPv4() const noexcept {
    return !data_.empty() && (data_[0] >> 4) == 4;
  }
  virtual bool IsIPv6() const noexcept {
    return !data_.empty() && (data_[0] >> 4) == 6;
  }

  std::size_t Size() const noexcept { return data_.size(); }
  const IPPacketData& Data() const noexcept { return data_; }
  // const IPPacket* GetRawPacket() const noexcept { return this; }

  IPv4Address GetSrcIPv4Address() const noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return {};
    }
    char buf[INET_ADDRSTRLEN] = {};
    const std::uint32_t net = Ipv4GetSrc(data_.data());
    ::inet_ntop(AF_INET, &net, buf, sizeof(buf));
    return IPv4Address(buf);
  }

  IPv4Address GetDstIPv4Address() const noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return {};
    }
    char buf[INET_ADDRSTRLEN] = {};
    const std::uint32_t net = Ipv4GetDst(data_.data());
    ::inet_ntop(AF_INET, &net, buf, sizeof(buf));
    return IPv4Address(buf);
  }

  IPv6Address GetSrcIPv6Address() const noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return {};
    }
    char buf[INET6_ADDRSTRLEN] = {};
    std::uint8_t addr[16] = {};
    Ipv6GetSrc(data_.data(), addr);
    ::inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return IPv6Address(buf);
  }

  IPv6Address GetDstIPv6Address() const noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return {};
    }
    char buf[INET6_ADDRSTRLEN] = {};
    std::uint8_t addr[16] = {};
    Ipv6GetDst(data_.data(), addr);
    ::inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return IPv6Address(buf);
  }

  void SetDstIPv4Address(const IPv4Address& dst) noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return;
    }
    std::uint8_t* p = data_.data();

    if (detail::Ipv4Ttl(p) == 0) {
      return;
    }

    const std::uint32_t addr = htonl(dst.ToInt());
    Ipv4SetDst(p, addr);
    RecalculateChecksums(p, data_.size());
  }

  void SetSrcIPv4Address(const IPv4Address& src) noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return;
    }
    std::uint8_t* p = data_.data();
    if (detail::Ipv4Ttl(p) == 0) {
      return;
    }
    const std::uint32_t addr = htonl(src.ToInt());
    Ipv4SetSrc(p, addr);
    RecalculateChecksums(p, data_.size());
  }

  void SetDstIPv6Address(const IPv6Address& dst) noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return;
    }
    std::uint8_t addr[16] = {};
    if (::inet_pton(AF_INET6, dst.ToString().c_str(), addr) != 1) {
      SPDLOG_WARN("IPPacket::SetDstIPv6Address – invalid '{}'", dst.ToString());
      return;
    }
    Ipv6SetDst(data_.data(), addr);
    RecalculateChecksums(data_.data(), data_.size());
  }

  void SetSrcIPv6Address(const IPv6Address& src) noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return;
    }
    std::uint8_t addr[16] = {};
    if (::inet_pton(AF_INET6, src.ToString().c_str(), addr) != 1) {
      SPDLOG_WARN("IPPacket::SetSrcIPv6Address – invalid '{}'", src.ToString());
      return;
    }
    Ipv6SetSrc(data_.data(), addr);
    RecalculateChecksums(data_.data(), data_.size());
  }

  bool IsICMPv4() const noexcept {
    return IsIPv4() && data_.size() >= detail::kMinIPv4 &&
           detail::Ipv4Proto(data_.data()) == 1u;
  }
  bool IsICMPv6() const noexcept {
    return IsIPv6() && data_.size() >= detail::kMinIPv6 &&
           detail::Ipv6Next(data_.data()) == 58u;
  }

  std::pair<const std::uint8_t*, std::size_t> GetTcpPayload() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t proto =
        IsIPv4() ? detail::Ipv4Proto(p) : detail::Ipv6Next(p);
    if (proto != 6u) {
      return {nullptr, 0};
    }
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 20) {
      return {nullptr, 0};
    }
    const std::uint8_t* tcp = p + ip_hdr;
    const std::size_t tcp_hdr = (tcp[12] >> 4) * 4;
    if (data_.size() < ip_hdr + tcp_hdr) {
      return {nullptr, 0};
    }
    return {tcp + tcp_hdr, data_.size() - ip_hdr - tcp_hdr};
  }

  std::pair<const std::uint8_t*, std::size_t> GetUdpPayload() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t proto =
        IsIPv4() ? detail::Ipv4Proto(p) : detail::Ipv6Next(p);
    if (proto != 17u) {
      return {nullptr, 0};
    }
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + detail::kUdpHdr) {
      return {nullptr, 0};
    }
    return {
        p + ip_hdr + detail::kUdpHdr, data_.size() - ip_hdr - detail::kUdpHdr};
  }

  bool IsDns() const noexcept { return DnsPtr() != nullptr; }

  std::optional<std::string> GetDnsDomain() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return std::nullopt;
    }
    if (ReadU16Be(dns + 4) == 0) {
      return std::nullopt;  // qdcount == 0
    }
    const std::uint8_t* cur = dns + detail::kDnsHdr;
    std::string name =
        detail::ParseDnsName(dns, data_.data() + data_.size(), cur);
    if (name.empty()) {
      return std::nullopt;
    }
#ifdef FPTN_WITH_LIBIDN2
    if (detail::IsPunycode(name)) return detail::ToUnicode(name);
#endif
    return name;
  }

  std::vector<IPv4Address> GetDnsIPv4Addresses() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return {};
    }
    const std::uint8_t* end = data_.data() + data_.size();
    int ancount = 0;
    const std::uint8_t* cur = detail::DnsAnswerStart(dns, end, &ancount);
    if (!cur) {
      return {};
    }

    std::vector<IPv4Address> out;
    for (int a = 0; a < ancount && cur < end; ++a) {
      // skip NAME
      for (int s = 0; s < 256 && cur < end; ++s) {
        const std::uint8_t l = *cur;
        if (l == 0u) {
          ++cur;
          break;
        }
        if ((l & 0xC0u) == 0xC0u) {
          cur += 2;
          break;
        }
        cur += 1 + l;
      }
      if (cur + 10 > end) {
        break;
      }

      const std::uint16_t rtype = ReadU16Be(cur);
      cur += 8;  // TYPE + CLASS + TTL
      const std::uint16_t rdlen = ReadU16Be(cur);
      cur += 2;

      if (cur + rdlen > end) {
        break;
      }
      if (rtype == 1u && rdlen == 4u) {  // A record
        char buf[INET_ADDRSTRLEN] = {};
        const std::uint32_t net =
            htonl((static_cast<std::uint32_t>(cur[0]) << 24) |
                  (static_cast<std::uint32_t>(cur[1]) << 16) |
                  (static_cast<std::uint32_t>(cur[2]) << 8) |
                  static_cast<std::uint32_t>(cur[3]));
        if (::inet_ntop(AF_INET, &net, buf, sizeof(buf))) {
          out.emplace_back(buf);
        }
      }
      cur += rdlen;
    }
    return out;
  }

  std::vector<IPv6Address> GetDnsIPv6Addresses() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return {};
    }
    const std::uint8_t* end = data_.data() + data_.size();
    int ancount = 0;
    const std::uint8_t* cur = detail::DnsAnswerStart(dns, end, &ancount);
    if (!cur) {
      return {};
    }

    std::vector<IPv6Address> out;
    for (int a = 0; a < ancount && cur < end; ++a) {
      // skip NAME
      for (int s = 0; s < 256 && cur < end; ++s) {
        const std::uint8_t l = *cur;
        if (l == 0u) {
          ++cur;
          break;
        }
        if ((l & 0xC0u) == 0xC0u) {
          cur += 2;
          break;
        }
        cur += 1 + l;
      }
      if (cur + 10 > end) {
        break;
      }
      const std::uint16_t rtype = ReadU16Be(cur);
      cur += 8;  // TYPE + CLASS + TTL
      const std::uint16_t rdlen = ReadU16Be(cur);
      cur += 2;
      if (cur + rdlen > end) {
        break;
      }
      if (rtype == 28u && rdlen == 16u) {  // AAAA record
        char buf[INET6_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET6, cur, buf, sizeof(buf))) {
          out.emplace_back(buf);
        }
      }
      cur += rdlen;
    }
    return out;
  }

 protected:
  IPPacket() : client_id_(FPTN_PACKET_UNDEFINED_CLIENT_ID) {}  // for tests

  const std::uint8_t* DnsPtr() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t* end = p + data_.size();
    if (IsIPv4() && data_.size() >= detail::kMinIPv4 &&
        detail::Ipv4Proto(p) == 17u) {
      return detail::DnsPayloadPtr(p + detail::Ipv4Ihl(p), end);
    }
    if (IsIPv6() && data_.size() >= detail::kMinIPv6 &&
        detail::Ipv6Next(p) == 17u) {
      return detail::DnsPayloadPtr(p + detail::kMinIPv6, end);
    }
    return nullptr;
  }

 private:
  IPPacketData data_;
  fptn::ClientID client_id_;
};

using IPPacketPtr = std::unique_ptr<IPPacket>;

#ifdef USING_MIMALLOC
using BatchIPPacketPtr =
    std::vector<IPPacketPtr, mi_stl_allocator<IPPacketPtr>>;  // NOLINT
#else
using BatchIPPacketPtr = std::vector<IPPacketPtr>;
#endif

}  // namespace fptn::common::network
