/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace fptn::common::network {

inline std::uint16_t ReadU16Be(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) << 8) |
         p[1];
}

inline void WriteU16Be(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v & 0xFFu);
}

// RFC 1071 one's-complement checksum.
// |data|   – pointer to the buffer to checksum.
// |len|    – number of bytes (may be odd).
// |sum|    – optional seed for pseudo-header pre-accumulation.
// Returns the final 16-bit one's-complement sum (ready to write into the
// checksum field; already bit-inverted).
inline std::uint16_t Rfc1071(
    const std::uint8_t* data, int len, std::uint32_t sum = 0u) {
  while (len > 1) {
    sum += (static_cast<std::uint32_t>(data[0]) << 8) |
           static_cast<std::uint32_t>(data[1]);
    data += 2;
    len -= 2;
  }
  if (len != 0) {
    sum += static_cast<std::uint32_t>(data[0]) << 8;
  }
  // Fold 32-bit sum into 16 bits.
  while ((sum >> 16) != 0u) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(~sum);
}

// IPv4 address accessors (network byte order preserved).
// Offsets per RFC 791: src = 12..15, dst = 16..19.
inline std::uint32_t Ipv4GetSrc(const std::uint8_t* p) {
  std::uint32_t addr = 0;
  std::memcpy(&addr, p + 12, 4);
  return addr;
}

inline std::uint32_t Ipv4GetDst(const std::uint8_t* p) {
  std::uint32_t addr = 0;
  std::memcpy(&addr, p + 16, 4);
  return addr;
}

inline void Ipv4SetSrc(std::uint8_t* p, std::uint32_t addr) {
  std::memcpy(p + 12, &addr, 4);
}

inline void Ipv4SetDst(std::uint8_t* p, std::uint32_t addr) {
  std::memcpy(p + 16, &addr, 4);
}

// IPv6 address accessors.
// Offsets per RFC 8200: src = 8..23, dst = 24..39.
inline void Ipv6GetSrc(const std::uint8_t* p, std::uint8_t out[16]) {
  std::memcpy(out, p + 8, 16);
}

inline void Ipv6GetDst(const std::uint8_t* p, std::uint8_t out[16]) {
  std::memcpy(out, p + 24, 16);
}

inline void Ipv6SetSrc(std::uint8_t* p, const std::uint8_t addr[16]) {
  std::memcpy(p + 8, addr, 16);
}

inline void Ipv6SetDst(std::uint8_t* p, const std::uint8_t addr[16]) {
  std::memcpy(p + 24, addr, 16);
}

// Checksum recalculation – IPv4
// Recalculates the IPv4 header checksum in-place (RFC 791 §3.1).
// |p| must point to the first byte of a valid IPv4 packet.
inline void ChecksumIpv4Header(std::uint8_t* p) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  WriteU16Be(p + 10, 0u);
  WriteU16Be(p + 10, Rfc1071(p, ihl));
}

// Recalculates the TCP checksum over an IPv4 packet in-place (RFC 793).
// |p| must point to the first byte of a valid IPv4/TCP packet.
inline void ChecksumTcpIpv4(std::uint8_t* p, std::size_t buf_size) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  if (buf_size < static_cast<std::size_t>(ihl) + 18) {
    return;
  }
  const int tcp_len = std::min(static_cast<int>(ReadU16Be(p + 2)) - ihl,
      static_cast<int>(buf_size) - ihl);
  if (tcp_len <= 0) {
    return;
  }
  std::uint8_t* tcp = p + ihl;

  // Build the 12-byte IPv4 pseudo-header (RFC 793 §3.1).
  std::uint8_t ph[12] = {};
  std::memcpy(ph + 0, p + 12, 4);  // source address
  std::memcpy(ph + 4, p + 16, 4);  // destination address
  ph[8] = 0u;                      // zero
  ph[9] = 6u;                      // protocol = TCP
  WriteU16Be(ph + 10, static_cast<std::uint16_t>(tcp_len));

  std::uint32_t sum = 0u;
  for (int i = 0; i < 12; i += 2) {
    sum += (static_cast<std::uint32_t>(ph[i]) << 8) |
           static_cast<std::uint32_t>(ph[i + 1]);
  }

  WriteU16Be(tcp + 16, 0u);
  WriteU16Be(tcp + 16, Rfc1071(tcp, tcp_len, sum));
}

// Recalculates the UDP checksum over an IPv4 packet in-place (RFC 768).
// A computed value of 0 is replaced with 0xFFFF per the RFC.
// |p| must point to the first byte of a valid IPv4/UDP packet.
inline void ChecksumUdpIpv4(std::uint8_t* p, std::size_t buf_size) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  if (buf_size < static_cast<std::size_t>(ihl) + 8) {
    return;
  }
  const int udp_len = std::min(static_cast<int>(ReadU16Be(p + 2)) - ihl,
      static_cast<int>(buf_size) - ihl);
  if (udp_len <= 0) {
    return;
  }
  std::uint8_t* udp = p + ihl;

  // Build the 12-byte IPv4 pseudo-header (RFC 768).
  std::uint8_t ph[12] = {};
  std::memcpy(ph + 0, p + 12, 4);  // source address
  std::memcpy(ph + 4, p + 16, 4);  // destination address
  ph[8] = 0u;                      // zero
  ph[9] = 17u;                     // protocol = UDP
  WriteU16Be(ph + 10, static_cast<std::uint16_t>(udp_len));

  std::uint32_t sum = 0u;
  for (int i = 0; i < 12; i += 2) {
    sum += (static_cast<std::uint32_t>(ph[i]) << 8) |
           static_cast<std::uint32_t>(ph[i + 1]);
  }

  WriteU16Be(udp + 6, 0u);
  std::uint16_t ck = Rfc1071(udp, udp_len, sum);
  if (ck == 0u) {  // cppcheck-suppress knownConditionTrueFalse
    ck = 0xFFFFu;  // RFC 768: transmit 0xFFFF instead of 0.
  }
  WriteU16Be(udp + 6, ck);
}

// Recalculates the ICMPv4 checksum in-place (RFC 792).
// |p| must point to the first byte of a valid IPv4/ICMP packet.
inline void ChecksumIcmpIpv4(std::uint8_t* p, std::size_t buf_size) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  if (buf_size < static_cast<std::size_t>(ihl) + 4) {
    return;
  }
  const int icmp_len = std::min(static_cast<int>(ReadU16Be(p + 2)) - ihl,
      static_cast<int>(buf_size) - ihl);
  if (icmp_len <= 0) {
    return;
  }
  std::uint8_t* icmp = p + ihl;

  WriteU16Be(icmp + 2, 0u);
  WriteU16Be(icmp + 2, Rfc1071(icmp, icmp_len));
}

// ---------------------------------------------------------------------------
// Checksum recalculation – IPv6
//
// NOTE: These functions assume there are no IPv6 extension headers between
// the fixed 40-byte IPv6 header and the transport layer payload.  The
// Payload Length field (bytes 4..5) is used directly as the transport-
// layer length.  Packets with extension headers must be pre-processed by
// the caller before invoking these helpers.
// ---------------------------------------------------------------------------

// Recalculates the TCP checksum over an IPv6 packet in-place (RFC 2460 §8.1).
// |p| must point to the first byte of a valid IPv6/TCP packet.
inline void ChecksumTcpIpv6(std::uint8_t* p, std::size_t buf_size) {
  if (buf_size < 40 + 18) {
    return;
  }
  const int tcp_len = std::min(
      static_cast<int>(ReadU16Be(p + 4)), static_cast<int>(buf_size) - 40);
  if (tcp_len <= 0) {
    return;
  }
  std::uint8_t* tcp = p + 40;

  // Build the 40-byte IPv6 pseudo-header (RFC 2460 §8.1).
  std::uint8_t ph[40] = {};
  std::memcpy(ph + 0, p + 8, 16);    // source address
  std::memcpy(ph + 16, p + 24, 16);  // destination address
  WriteU16Be(ph + 34, static_cast<std::uint16_t>(tcp_len));
  ph[39] = 6u;  // next header = TCP

  std::uint32_t sum = 0u;
  for (int i = 0; i < 40; i += 2) {
    sum += (static_cast<std::uint32_t>(ph[i]) << 8) |
           static_cast<std::uint32_t>(ph[i + 1]);
  }

  WriteU16Be(tcp + 16, 0u);
  WriteU16Be(tcp + 16, Rfc1071(tcp, tcp_len, sum));
}

// Recalculates the UDP checksum over an IPv6 packet in-place (RFC 2460 §8.1).
// A computed value of 0 is replaced with 0xFFFF per RFC 768.
// |p| must point to the first byte of a valid IPv6/UDP packet.
inline void ChecksumUdpIpv6(std::uint8_t* p, std::size_t buf_size) {
  if (buf_size < 40 + 8) {
    return;
  }
  const int udp_len = std::min(
      static_cast<int>(ReadU16Be(p + 4)), static_cast<int>(buf_size) - 40);
  if (udp_len <= 0) {
    return;
  }
  std::uint8_t* udp = p + 40;

  // Build the 40-byte IPv6 pseudo-header (RFC 2460 §8.1).
  std::uint8_t ph[40] = {};
  std::memcpy(ph + 0, p + 8, 16);    // source address
  std::memcpy(ph + 16, p + 24, 16);  // destination address
  WriteU16Be(ph + 34, static_cast<std::uint16_t>(udp_len));
  ph[39] = 17u;  // next header = UDP

  std::uint32_t sum = 0u;
  for (int i = 0; i < 40; i += 2) {
    sum += (static_cast<std::uint32_t>(ph[i]) << 8) |
           static_cast<std::uint32_t>(ph[i + 1]);
  }

  WriteU16Be(udp + 6, 0u);
  std::uint16_t ck = Rfc1071(udp, udp_len, sum);
  if (ck == 0u) {  // cppcheck-suppress knownConditionTrueFalse
    ck = 0xFFFFu;  // RFC 768: transmit 0xFFFF instead of 0.
  }
  WriteU16Be(udp + 6, ck);
}

// Recalculates the ICMPv6 checksum over an IPv6 packet in-place (RFC 4443
// §2.3). |p| must point to the first byte of a valid IPv6/ICMPv6 packet.
inline void ChecksumIcmpv6Ipv6(std::uint8_t* p, std::size_t buf_size) {
  if (buf_size < 40 + 4) {
    return;
  }
  const int icmp_len = std::min(
      static_cast<int>(ReadU16Be(p + 4)), static_cast<int>(buf_size) - 40);
  if (icmp_len <= 0) {
    return;
  }
  std::uint8_t* icmp = p + 40;

  // Build the 40-byte IPv6 pseudo-header (RFC 2460 §8.1).
  std::uint8_t ph[40] = {};
  std::memcpy(ph + 0, p + 8, 16);    // source address
  std::memcpy(ph + 16, p + 24, 16);  // destination address
  WriteU16Be(ph + 34, static_cast<std::uint16_t>(icmp_len));
  ph[39] = 58u;  // next header = ICMPv6

  std::uint32_t sum = 0u;
  for (int i = 0; i < 40; i += 2) {
    sum += (static_cast<std::uint32_t>(ph[i]) << 8) |
           static_cast<std::uint32_t>(ph[i + 1]);
  }

  WriteU16Be(icmp + 2, 0u);
  WriteU16Be(icmp + 2, Rfc1071(icmp, icmp_len, sum));
}

// Recalculates all relevant checksums for the IP packet starting at |p|.
// Supports IPv4 (TCP/UDP/ICMP) and IPv6 (TCP/UDP/ICMPv6).
// For IPv4, the transport checksum is computed first, then the IP header
// checksum – this order is required because the IP header must be correct
// before being sent but the transport pseudo-header does not include the
// header checksum field.
// Unknown protocol numbers are silently ignored.
inline void RecalculateChecksums(std::uint8_t* p, std::size_t buf_size) {
  if (buf_size < 1) {
    return;
  }
  const std::uint8_t version = p[0] >> 4;

  if (version == 4) {
    if (buf_size < 20) {
      return;
    }
    // Recalculate transport checksum first (it doesn't depend on the IP
    // header checksum field), then fix up the IP header checksum.
    switch (p[9]) {
      case 6:  // TCP
        ChecksumTcpIpv4(p, buf_size);
        break;
      case 17:  // UDP
        ChecksumUdpIpv4(p, buf_size);
        break;
      case 1:  // ICMP
        ChecksumIcmpIpv4(p, buf_size);
        break;
      default:
        break;
    }
    ChecksumIpv4Header(p);
  } else if (version == 6u) {
    if (buf_size < 40) {
      return;
    }
    switch (p[6]) {
      case 6:  // TCP
        ChecksumTcpIpv6(p, buf_size);
        break;
      case 17:  // UDP
        ChecksumUdpIpv6(p, buf_size);
        break;
      case 58u:  // ICMPv6
        ChecksumIcmpv6Ipv6(p, buf_size);
        break;
      default:
        break;
    }
  }
}

// Returns true if the UDP payload is a DNS *response* (QR bit == 1).
// |p| must point to the first byte of a valid IPv4/UDP packet.
inline bool IsDnsResponseIPv4(const std::uint8_t* p, std::size_t buf_size) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  const std::uint8_t* dns = p + ihl + 8;  // skip UDP header (8 bytes)
  if (p + buf_size < dns + 3) {
    return false;
  }
  // DNS flags are at offset 2..3 in the DNS header.
  // QR bit is the most-significant bit of the first flags byte.
  return (dns[2] & 0x80u) != 0u;
}

// Parses the Question Section of a DNS message and returns all queried domain
// names as a vector of strings (e.g. {"example.com", "www.google.com"}).
// |p| must point to the first byte of a valid IPv4/UDP packet whose payload
// is a DNS message (query or response – the Question Section is present in
// both).
// Returns an empty vector if the packet is malformed or contains no questions.
inline std::vector<std::string> DnsGetQueriedDomainsIPv4(
    const std::uint8_t* p, int total_len) {
  const int ihl = (p[0] & 0x0Fu) * 4;
  if (total_len < ihl + 8) {
    return {};
  }
  const std::uint8_t* udp = p + ihl;
  const int udp_len = static_cast<int>(ReadU16Be(udp + 4));  // UDP length field
  const int safe_udp_len = std::min(udp_len, total_len - ihl);
  const std::uint8_t* dns = udp + 8;
  const int dns_len = safe_udp_len - 8;

  if (dns_len < 12) {
    return {};  // need at least the 12-byte DNS header
  }

  const int qdcount = static_cast<int>(ReadU16Be(dns + 4));  // question count
  if (qdcount == 0) {
    return {};
  }

  std::vector<std::string> domains;
  const std::uint8_t* cur = dns + 12;  // start of Question Section
  const std::uint8_t* end = dns + dns_len;
  for (int q = 0; q < qdcount && cur < end; ++q) {
    std::string name;

    // Parse a DNS name: sequence of length-prefixed labels, terminated by 0x00.
    while (cur < end) {
      const std::uint8_t label_len = *cur++;
      if (label_len == 0u) {
        break;  // root label – end of name
      }
      // Pointer compression (RFC 1035 §4.1.4) is not expected in the
      // Question Section of a fresh query, but guard against it anyway.
      if ((label_len & 0xC0u) == 0xC0u) {
        ++cur;  // skip the second pointer byte
        break;
      }

      if (cur + label_len > end) {
        return domains;  // malformed
      }
      if (!name.empty()) {
        name += '.';
      }
      name.append(reinterpret_cast<const char*>(cur), label_len);
      cur += label_len;
    }

    if (cur + 4 > end) {
      return domains;  // need QTYPE + QCLASS (4 bytes)
    }
    cur += 4;  // skip QTYPE and QCLASS
    if (!name.empty()) {
      domains.push_back(std::move(name));
    }
  }
  return domains;
}

inline bool IsTlsClientHello(
    const std::uint8_t* data, std::size_t len) noexcept {
  if (!data || len < 6) {
    return false;
  }
  if (data[0] != 0x16u) {
    return false;
  }
  const std::uint16_t ver = (static_cast<std::uint16_t>(data[1]) << 8) |
                            static_cast<std::uint16_t>(data[2]);
  if (ver < 0x0301u || ver > 0x0304u) {
    return false;
  }
  return data[5] == 0x01u;
}

inline std::optional<std::string> GetTlsSNI(
    const std::uint8_t* data, std::size_t len) noexcept {
  // TLS record(5) + HS type(1) + HS length(3) + legacy_version(2) + random(32)
  const std::uint8_t* p = data + 43;
  const std::uint8_t* end = data + len;

  if (p + 1 > end) {
    return std::nullopt;
  }

  p += 1 + *p;

  // cipher_suites
  if (p + 2 > end) {
    return std::nullopt;
  }
  p += 2 + ((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);

  // compression_methods
  if (p + 1 > end) {
    return std::nullopt;
  }
  p += 1 + *p;

  // extensions length
  if (p + 2 > end) {
    return std::nullopt;
  }
  const std::uint8_t* ext_end =
      p + 2 + ((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
  p += 2;
  if (ext_end > end) {
    return std::nullopt;
  }
  while (p + 4 <= ext_end) {
    const std::uint16_t type = (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
    const std::uint16_t elen = (static_cast<std::uint16_t>(p[2]) << 8) | p[3];
    p += 4;
    if (p + elen > ext_end) {
      return std::nullopt;
    }
    if (type == 0x0000u && elen >= 5) {
      // SNI list_len(2) + name_type(1) + name_len(2) + name
      const std::uint16_t name_len =
          (static_cast<std::uint16_t>(p[3]) << 8) | p[4];
      if (p + 5 + name_len > ext_end) {
        return std::nullopt;
      }
      return std::string(reinterpret_cast<const char*>(p + 5), name_len);
    }
    p += elen;
  }
  return std::nullopt;
}

inline std::vector<std::uint8_t> GetTlsSessionId(
    const std::uint8_t* data, std::size_t len) noexcept {
  // TLS record(5) + HS type(1) + HS length(3) + legacy_version(2) + random(32)
  const std::uint8_t* p = data + 43;
  const std::uint8_t* end = data + len;

  if (p + 1 > end) {
    return {};
  }
  const std::uint8_t sid_len = *p++;
  if (p + sid_len > end) {
    return {};
  }
  return {p, p + sid_len};
}

}  // namespace fptn::common::network
