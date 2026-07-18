/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <fcntl.h>
#include <linux/if_tun.h>
// <linux/virtio_net.h> declares a struct member named `class`, valid in C
// but a reserved word in C++. Rename it for the duration of the include so
// we can still use the system UAPI header (struct virtio_net_hdr et al).
#define class class_
#include <linux/virtio_net.h>
#undef class
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <deque>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"

// USO offload flags and gso type appeared in kernel 6.2 headers
#ifndef TUN_F_USO4
#define TUN_F_USO4 0x20
#endif
#ifndef TUN_F_USO6
#define TUN_F_USO6 0x40
#endif
#ifndef VIRTIO_NET_HDR_GSO_UDP_L4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#endif

namespace fptn::common::network {

/**
 * Linux TUN device with GSO batching (IFF_VNET_HDR).
 *
 * With TUNSETOFFLOAD enabled the kernel coalesces (GRO) consecutive TCP/UDP
 * packets into super-frames of up to 64KB, so a single read() delivers what
 * would otherwise take dozens of syscalls. Super-frames are split back into
 * MTU-sized packets in userspace and buffered in an internal queue, keeping
 * the external one-packet-per-call Read()/Write() API intact.
 */
class LinuxTunDevice {
 public:
  ~LinuxTunDevice() { Close(); }

  bool Open(const std::string& name) {
    fd_ = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd_ < 0) {
      SPDLOG_ERROR("Failed to open /dev/net/tun: {}", strerror(errno));
      return false;
    }

    struct ifreq ifr = {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name.c_str());
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
    if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
      // Fallback: plain TUN without vnet header (no GSO batching)
      SPDLOG_WARN("IFF_VNET_HDR unsupported, falling back to plain TUN");
      std::memset(&ifr, 0, sizeof(ifr));
      std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name.c_str());
      ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
      if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        SPDLOG_ERROR("TUNSETIFF failed: {}", strerror(errno));
        Close();
        return false;
      }
      vnet_hdr_ = false;
    } else {
      vnet_hdr_ = true;
    }
    name_ = ifr.ifr_name;

    if (vnet_hdr_) {
      int hdr_size = sizeof(struct virtio_net_hdr);
      if (::ioctl(fd_, TUNSETVNETHDRSZ, &hdr_size) < 0) {
        SPDLOG_WARN("TUNSETVNETHDRSZ failed: {}", strerror(errno));
      }
      // Advertise which offloads userspace accepts: enables kernel-side
      // GRO coalescing of inbound traffic into GSO super-frames.
      const unsigned int base = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
      if (::ioctl(fd_, TUNSETOFFLOAD, base | TUN_F_USO4 | TUN_F_USO6) < 0 &&
          ::ioctl(fd_, TUNSETOFFLOAD, base) < 0) {
        SPDLOG_WARN("TUNSETOFFLOAD failed: {}", strerror(errno));
      }
    }

    read_buf_.resize(sizeof(struct virtio_net_hdr) + kMaxFrameSize);
    return true;
  }

  void Close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
    pending_.clear();
  }

  [[nodiscard]] const std::string& GetName() const { return name_; }

  bool ConfigureIPv4(const std::string& addr, int mask) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      return false;
    }

    struct ifreq ifr = {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name_.c_str());
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    if (::inet_pton(AF_INET, addr.c_str(), &sin->sin_addr) != 1 ||
        ::ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
      SPDLOG_ERROR("SIOCSIFADDR({}) failed: {}", addr, strerror(errno));
      ::close(sock);
      return false;
    }

    sin->sin_addr.s_addr =
        (mask == 0) ? 0 : htonl(~0u << (32 - static_cast<unsigned>(mask)));
    if (::ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
      SPDLOG_ERROR("SIOCSIFNETMASK(/{}) failed: {}", mask, strerror(errno));
      ::close(sock);
      return false;
    }
    ::close(sock);
    return true;
  }

  bool ConfigureIPv6(const std::string& addr, int prefixlen) {
    const int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
      return false;
    }

    // struct in6_ifreq from <linux/ipv6.h> (defined locally to avoid
    // conflicts between kernel and libc headers)
    struct In6Ifreq {
      struct in6_addr addr;
      std::uint32_t prefixlen;
      int ifindex;
    } req = {};

    req.ifindex = static_cast<int>(::if_nametoindex(name_.c_str()));
    req.prefixlen = static_cast<std::uint32_t>(prefixlen);
    if (req.ifindex == 0 ||
        ::inet_pton(AF_INET6, addr.c_str(), &req.addr) != 1 ||
        ::ioctl(sock, SIOCSIFADDR, &req) < 0) {
      SPDLOG_WARN("IPv6 SIOCSIFADDR({}) failed: {}", addr, strerror(errno));
      ::close(sock);
      return false;
    }
    ::close(sock);
    return true;
  }

  void SetNonBlocking(bool enabled) {
    const int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags >= 0) {
      ::fcntl(fd_, F_SETFL,
          enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
    }
  }

  void SetMTU(int mtu) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      return;
    }
    struct ifreq ifr = {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name_.c_str());
    ifr.ifr_mtu = mtu;
    if (::ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
      SPDLOG_ERROR("SIOCSIFMTU({}) failed: {}", mtu, strerror(errno));
    }
    ::close(sock);
  }

  void BringUp() {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      return;
    }
    struct ifreq ifr = {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name_.c_str());
    if (::ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
      ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
      if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        SPDLOG_ERROR("SIOCSIFFLAGS(up) failed: {}", strerror(errno));
      }
    }
    ::close(sock);
  }

  int Read(void* buffer, int size) {
    if (pending_.empty() && !FillPending()) {
      return 0;
    }
    const auto& front = pending_.front();
    if (static_cast<int>(front.size()) > size) {
      SPDLOG_WARN("Dropping oversized segment ({} > {})", front.size(), size);
      pending_.pop_front();
      return 0;
    }
    const int len = static_cast<int>(front.size());
    std::memcpy(buffer, front.data(), front.size());
    pending_.pop_front();
    return len;
  }

  int Write(const void* data, int size) {
    if (!vnet_hdr_) {
      return static_cast<int>(::write(fd_, data, size));
    }
    // Every write must carry a virtio_net_hdr; zeroed = plain packet
    // (gso NONE, checksums already computed by the sender).
    struct virtio_net_hdr hdr = {};
    struct iovec iov[2] = {
        {&hdr, sizeof(hdr)},
        {const_cast<void*>(data), static_cast<std::size_t>(size)},
    };
    const ssize_t written = ::writev(fd_, iov, 2);
    if (written != static_cast<ssize_t>(sizeof(hdr)) + size) {
      return -1;
    }
    return size;
  }

  // cppcheck-suppress functionStatic
  void SetStopFlag(const std::atomic<bool>* /*running*/) {}

 private:
  using Segment = std::vector<std::uint8_t>;

  // One read() syscall -> a super-frame -> many MTU-sized packets queued.
  bool FillPending() {
    const ssize_t n = ::read(fd_, read_buf_.data(), read_buf_.size());
    if (n <= 0) {
      return false;
    }
    if (!vnet_hdr_) {
      pending_.emplace_back(read_buf_.data(), read_buf_.data() + n);
      return true;
    }
    if (static_cast<std::size_t>(n) <= sizeof(struct virtio_net_hdr)) {
      return false;
    }
    struct virtio_net_hdr hdr = {};
    std::memcpy(&hdr, read_buf_.data(), sizeof(hdr));
    return SegmentGsoFrame(read_buf_.data() + sizeof(hdr),
        static_cast<std::size_t>(n) - sizeof(hdr), hdr);
  }

  // Sum of the source+destination addresses as 16-bit words — the address
  // part of the transport pseudo-header (RFC 793/8200). src and dst are
  // adjacent in both IPv4 (bytes 12..20) and IPv6 (bytes 8..40) headers.
  static std::uint32_t AddrPairSum(const std::uint8_t* frame, bool v6) {
    const std::uint8_t* p = v6 ? frame + 8 : frame + 12;
    const std::size_t len = v6 ? 32 : 8;
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < len; i += 2) {
      sum += (static_cast<std::uint32_t>(p[i]) << 8) |
             static_cast<std::uint32_t>(p[i + 1]);
    }
    return sum;
  }

  // Splits a GSO super-frame into standalone MTU-sized IP packets with
  // recalculated lengths, sequence numbers, IDs and checksums, appending
  // them to |pending_|. Returns false (dropping the frame) when it is
  // malformed or the GSO type is unsupported.
  //
  // Modeled on wireguard-go tun/offload.go (handleVirtioRead + gsoSplit):
  // csum_start is used as the network-header length and hdr.hdr_len from
  // the kernel is not trusted (it can be the whole first packet length on
  // the FORWARD path).
  bool SegmentGsoFrame(const std::uint8_t* frame, std::size_t size,
      const struct virtio_net_hdr& hdr) {
    // Non-GSO frame: pass through. With VIRTIO_NET_HDR_F_NEEDS_CSUM
    // (CHECKSUM_PARTIAL) the kernel stored the pseudo-header sum at the
    // checksum field; finish it over [csum_start, end).
    if (hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE) {
      if ((hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0u) {
        const std::size_t csum_at =
            static_cast<std::size_t>(hdr.csum_start) + hdr.csum_offset;
        if (csum_at + 2 > size) {
          return false;
        }
        pending_.emplace_back(frame, frame + size);
        std::uint8_t* p = pending_.back().data();
        const std::uint32_t initial = ReadU16Be(p + csum_at);
        p[csum_at] = 0;
        p[csum_at + 1] = 0;
        WriteU16Be(p + csum_at,
            Rfc1071(p + hdr.csum_start,
                static_cast<int>(size - hdr.csum_start), initial));
      } else {
        pending_.emplace_back(frame, frame + size);
      }
      return true;
    }

    if (hdr.gso_size == 0u || size < 20u) {
      return false;
    }

    // Cross-check the IP version against the GSO type. ECN-marked types
    // are rejected: TUN_F_TSO_ECN is not advertised, so the kernel never
    // sends them (same as wireguard-go).
    const std::uint8_t ver = frame[0] >> 4;
    bool v6 = false;
    bool tcp = false;
    if (hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4) {
      if (ver != 4u) {
        return false;
      }
      tcp = true;
    } else if (hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6) {
      if (ver != 6u) {
        return false;
      }
      v6 = true;
      tcp = true;
    } else if (hdr.gso_type == VIRTIO_NET_HDR_GSO_UDP_L4) {
      if (ver != 4u && ver != 6u) {
        return false;
      }
      v6 = (ver == 6u);
    } else {
      return false;  // unsupported gso_type (legacy UFO, ECN, ...)
    }

    // csum_start is synonymous with the IP header length for GSO frames.
    const std::size_t ip_hdr_len = hdr.csum_start;
    if ((v6 && ip_hdr_len < 40u) || (!v6 && ip_hdr_len < 20u) ||
        size < ip_hdr_len) {
      return false;
    }
    std::size_t transport_hdr_len = 8;  // UDP
    if (tcp) {
      if (size <= ip_hdr_len + 12u) {
        return false;
      }
      transport_hdr_len =
          static_cast<std::size_t>(frame[ip_hdr_len + 12] >> 4) * 4u;
      if (transport_hdr_len < 20u) {
        return false;
      }
    }
    const std::size_t headers_len = ip_hdr_len + transport_hdr_len;
    const std::size_t csum_at =
        static_cast<std::size_t>(hdr.csum_start) + hdr.csum_offset;
    if (size < headers_len || csum_at + 2 > headers_len) {
      return false;
    }
    const std::size_t payload_len = size - headers_len;
    const std::size_t mss = hdr.gso_size;
    if (payload_len == 0u) {
      return false;
    }
    const std::size_t nsegs = (payload_len + mss - 1) / mss;
    if (nsegs > kMaxSegments) {
      return false;
    }

    const std::uint16_t base_ip_id = v6 ? 0u : ReadU16Be(frame + 4);
    const std::uint8_t* s = frame + ip_hdr_len + 4;
    const std::uint32_t first_seq =
        tcp ? (static_cast<std::uint32_t>(s[0]) << 24) |
                  (static_cast<std::uint32_t>(s[1]) << 16) |
                  (static_cast<std::uint32_t>(s[2]) << 8) |
                  static_cast<std::uint32_t>(s[3])
            : 0u;
    // Address part of the pseudo-header: constant across segments.
    const std::uint32_t addr_sum = AddrPairSum(frame, v6);
    const std::uint32_t proto = tcp ? IPPROTO_TCP : IPPROTO_UDP;

    std::size_t offset = 0;
    for (std::size_t i = 0; i < nsegs; ++i) {
      const std::size_t chunk =
          (payload_len - offset < mss) ? (payload_len - offset) : mss;
      const std::size_t l4_len = transport_hdr_len + chunk;
      const bool last = (i == nsegs - 1);

      Segment seg;
      seg.reserve(headers_len + chunk);
      seg.insert(seg.end(), frame, frame + headers_len);
      seg.insert(seg.end(), frame + headers_len + offset,
          frame + headers_len + offset + chunk);

      std::uint8_t* p = seg.data();
      if (v6) {
        WriteU16Be(p + 4, static_cast<std::uint16_t>(l4_len));
      } else {
        WriteU16Be(p + 2, static_cast<std::uint16_t>(headers_len + chunk));
        WriteU16Be(p + 4, static_cast<std::uint16_t>(base_ip_id + i));
        p[10] = 0;
        p[11] = 0;
        WriteU16Be(p + 10, Rfc1071(p, static_cast<int>(ip_hdr_len)));
      }

      std::uint8_t* tr = p + ip_hdr_len;
      if (tcp) {
        const std::uint32_t seq =
            first_seq + static_cast<std::uint32_t>(mss * i);
        tr[4] = static_cast<std::uint8_t>(seq >> 24);
        tr[5] = static_cast<std::uint8_t>(seq >> 16);
        tr[6] = static_cast<std::uint8_t>(seq >> 8);
        tr[7] = static_cast<std::uint8_t>(seq);
        if (!last) {
          tr[13] &= static_cast<std::uint8_t>(~(0x01u | 0x08u));  // FIN|PSH
        }
      } else {
        WriteU16Be(tr + 4, static_cast<std::uint16_t>(l4_len));
      }
      // Transport checksum: pseudo-header seed + one pass over L4 data.
      tr[hdr.csum_offset] = 0;
      tr[hdr.csum_offset + 1] = 0;
      WriteU16Be(tr + hdr.csum_offset,
          Rfc1071(tr, static_cast<int>(l4_len),
              addr_sum + proto + static_cast<std::uint32_t>(l4_len)));

      pending_.push_back(std::move(seg));
      offset += chunk;
    }
    return true;
  }

  static constexpr std::size_t kMaxFrameSize = 65535;
  // Sanity cap: 64KB frame / smallest sane MSS still fits well below this.
  static constexpr std::size_t kMaxSegments = 128;

  int fd_ = -1;
  bool vnet_hdr_ = false;
  std::string name_;
  std::vector<std::uint8_t> read_buf_;
  std::deque<Segment> pending_;
};

}  // namespace fptn::common::network
