/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "adblock/adblock.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#include <zlib.h>           // NOLINT(build/include_order)

#include "common/network/ip_utils.h"
#include "common/utils/utils.h"

namespace fptn::adblock {

extern const unsigned char kBlocklistGz[];
extern const unsigned int kBlocklistGzLen;

namespace {

namespace net = fptn::common::network;

constexpr std::size_t kUdpHdr = net::detail::kUdpHdr;
constexpr std::size_t kDnsHdr = net::detail::kDnsHdr;
constexpr std::size_t kMinIPv6 = net::detail::kMinIPv6;
constexpr std::uint16_t kQTypeA = 0x0001;
constexpr std::uint16_t kQTypeAAAA = 0x001C;

net::IPPacketPtr BuildResponse(const net::IPPacketData& in) {
  const std::uint8_t ver = in[0] >> 4;
  const std::size_t ip_hdr_len =
      (ver == 4) ? static_cast<std::size_t>(net::detail::Ipv4Ihl(in.data()))
                 : kMinIPv6;
  const std::size_t udp_off = ip_hdr_len;
  const std::size_t dns_off = udp_off + kUdpHdr;

  const std::uint8_t* base = in.data() + dns_off;
  const std::uint8_t* end = in.data() + in.size();

  const std::uint8_t* cur = base + kDnsHdr;
  net::detail::ParseDnsName(base, end, cur);
  const auto name_end = static_cast<std::size_t>(cur - in.data());
  if (name_end + 4 > in.size()) {
    return nullptr;
  }
  const std::uint16_t qtype = net::ReadU16Be(in.data() + name_end);
  const std::size_t question_end = name_end + 4;

  std::vector<std::uint8_t> rdata;
  bool null_route = true;
  if (qtype == kQTypeA) {
    rdata = {127, 0, 0, 1};
  } else if (qtype == kQTypeAAAA) {
    rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  } else {
    null_route = false;
  }

  net::IPPacketData resp;
  if (null_route) {
    const std::size_t answer_len = 12 + rdata.size();
    resp.assign(in.begin(), in.begin() + question_end);
    resp.resize(question_end + answer_len);

    std::size_t off = question_end;
    resp[off++] = 0xC0;
    resp[off++] = static_cast<std::uint8_t>(kDnsHdr);
    net::WriteU16Be(resp.data() + off, qtype);
    off += 2;
    net::WriteU16Be(resp.data() + off, 0x0001);
    off += 2;
    net::WriteU16Be(resp.data() + off, 0);
    off += 2;
    net::WriteU16Be(resp.data() + off, 600);
    off += 2;
    net::WriteU16Be(
        resp.data() + off, static_cast<std::uint16_t>(rdata.size()));
    off += 2;
    std::ranges::copy(rdata, resp.begin() + off);

    resp[dns_off + 2] =
        static_cast<std::uint8_t>((resp[dns_off + 2] & 0x01) | 0x80);
    resp[dns_off + 3] = 0x80;
    net::WriteU16Be(resp.data() + dns_off + 6, 1);
    net::WriteU16Be(resp.data() + dns_off + 8, 0);
    net::WriteU16Be(resp.data() + dns_off + 10, 0);
  } else {
    resp.assign(in.begin(), in.end());
    resp[dns_off + 2] =
        static_cast<std::uint8_t>((resp[dns_off + 2] & 0x01) | 0x80);
    resp[dns_off + 3] = 0x83;
  }

  const std::size_t new_len = resp.size();

  if (ver == 4) {
    for (int i = 0; i < 4; ++i) {
      std::swap(resp[12 + i], resp[16 + i]);
    }
    net::detail::Ipv4Ttl(resp.data()) = 64;
    net::WriteU16Be(resp.data() + 2, static_cast<std::uint16_t>(new_len));
  } else {
    for (int i = 0; i < 16; ++i) {
      std::swap(resp[8 + i], resp[24 + i]);
    }
    resp[7] = 64;
    net::WriteU16Be(
        resp.data() + 4, static_cast<std::uint16_t>(new_len - ip_hdr_len));
  }

  std::swap(resp[udp_off], resp[udp_off + 2]);
  std::swap(resp[udp_off + 1], resp[udp_off + 3]);
  net::WriteU16Be(
      resp.data() + udp_off + 4, static_cast<std::uint16_t>(new_len - udp_off));

  net::RecalculateChecksums(resp.data(), resp.size());
  return net::IPPacket::Parse(std::move(resp));
}

std::string Gunzip(const unsigned char* data, unsigned int size) {
  constexpr std::size_t kChunkSize = 64 * 1024;
  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data));
  strm.avail_in = size;
  if (::inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    return {};
  }

  std::string out;
  int ret = 0;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
    strm.avail_out = static_cast<unsigned int>(buffer.size());
    ret = ::inflate(&strm, Z_NO_FLUSH);
    if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      ::inflateEnd(&strm);
      return {};
    }
    out.append(buffer.data(), buffer.size() - strm.avail_out);
  } while (ret != Z_STREAM_END);

  ::inflateEnd(&strm);
  return out;
}

std::string ParseBlocklistLine(std::string line) {
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }
  if (line.empty() || line[0] == '#' || line[0] == '!') {
    return {};
  }
  const std::size_t comment = line.find('#');
  if (comment != std::string::npos) {
    line.erase(comment);
  }
  line = fptn::common::utils::ToLowerCase(fptn::common::utils::Trim(line));
  if (line.empty()) {
    return {};
  }

  const std::size_t sep = line.find_first_of(" \t");
  std::string domain = (sep == std::string::npos) ? line : line.substr(sep + 1);
  domain = fptn::common::utils::Trim(domain);
  const std::size_t dot = domain.find('.');
  if (dot == std::string::npos || domain == "0.0.0.0") {
    return {};
  }
  return domain;
}

std::unordered_set<std::string> LoadEmbeddedBlocklist() {
  std::unordered_set<std::string> domains;
  const std::string list = Gunzip(kBlocklistGz, kBlocklistGzLen);
  if (list.empty()) {
    SPDLOG_WARN(
        "Ad-block list could not be decompressed; ad blocking inactive");
    return domains;
  }

  std::size_t start = 0;
  while (start < list.size()) {
    std::size_t nl = list.find('\n', start);
    if (nl == std::string::npos) {
      nl = list.size();
    }
    std::string domain = ParseBlocklistLine(list.substr(start, nl - start));
    if (!domain.empty()) {
      domains.insert(std::move(domain));
    }
    start = nl + 1;
  }
  SPDLOG_INFO("Ad-block list loaded [domains={}]", domains.size());
  return domains;
}

}  // namespace

AdBlocker::AdBlocker() : AdBlocker(LoadEmbeddedBlocklist()) {}

AdBlocker::AdBlocker(std::unordered_set<std::string> blocked_domains)
    : blocked_domains_(std::move(blocked_domains)) {}

bool AdBlocker::IsBlocked(const std::string& domain) const {
  std::string d = domain;
  std::size_t dot = d.find('.');
  while (dot != std::string::npos) {
    if (blocked_domains_.contains(d)) {
      return true;
    }
    d = d.substr(dot + 1);
    dot = d.find('.');
  }
  return false;
}

fptn::common::network::IPPacketPtr AdBlocker::ProcessOutgoingDns(
    const fptn::common::network::IPPacket& packet) const {
  if (!packet.IsDns()) {
    return nullptr;
  }
  const auto domain = packet.GetDnsDomain();
  if (!domain || !IsBlocked(fptn::common::utils::ToLowerCase(*domain))) {
    return nullptr;
  }

  SPDLOG_INFO("Blocked DNS query [domain={}]", *domain);
  return BuildResponse(packet.Data());
}

}  // namespace fptn::adblock
