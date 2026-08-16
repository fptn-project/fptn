/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"

#include <cstring>
#include <memory>
#include <random>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "fptn-protocol-lib/time/time_provider.h"

namespace {

constexpr std::size_t kMmaxBufferSize = 1024 * 256;

enum {
  kFptnTlsApplicationHeaderType = 0x17,
  kFptnTlsApplicationHeaderMajor = 0x03,
  kFptnTlsApplicationHeaderMinor = 0x03
};

#pragma pack(push, 1)
struct TLSAppDataRecordHeader {
  /* Standard TLS header */
  std::uint8_t headertype;
  std::uint8_t headermajor;
  std::uint8_t headerminor;
  std::uint16_t content_length;  // Must be in network byte order!

  /* FPTN TLS obfuscator protocol */
  std::uint64_t random_data;
  std::uint32_t timestamp;  // Must be in network byte order!
  std::uint8_t xor_key;
  std::uint16_t payload_length;  // Must be in network byte order!
  std::uint16_t padding_length;  // Must be in network byte order!
  // std::uint8_t xor_payload[payload_length];
  // std::uint8_t padding[padding_length]
};
#pragma pack(pop)

std::uint16_t HostToNetwork16(const std::uint16_t value) {
  return htons(value);
}

std::uint16_t NetworkToHost16(const std::uint16_t value) {
  return ntohs(value);
}

std::uint32_t HostToNetwork32(const std::uint32_t value) {
  return htonl(value);
}

std::uint32_t NetworkToHost32(const std::uint32_t value) {
  return ntohl(value);
}

bool IsValidTimestamp(const std::uint32_t timestamp) {
  const auto now = fptn::time::TimeProvider::Instance()->NowTimestamp();
  constexpr std::uint32_t kTimeShiftSeconds = 120;

  return (timestamp <= now + kTimeShiftSeconds) &&
         (timestamp + kTimeShiftSeconds >= now);
}

std::uint64_t GetRandomData() {
  static std::mt19937 gen{std::random_device {}()};
  std::uniform_int_distribution<std::uint64_t> dist(1024, UINT64_MAX);
  return dist(gen);
}

std::uint8_t GetRandomByte(
    const std::uint8_t min = 0, const std::uint8_t max = UINT8_MAX) {
  static std::mt19937 gen{std::random_device {}()};
  std::uniform_int_distribution<std::uint16_t> dist(min, max);
  return static_cast<std::uint8_t>(dist(gen));
}

std::uint16_t GetRandomPaddingLength() {
  static std::mt19937 gen{std::random_device {}()};
  std::uniform_int_distribution<std::uint16_t> dist(4095, 8192);
  return dist(gen);
}

std::vector<std::uint8_t> GenerateRandomPadding(const std::size_t length) {
  std::vector<std::uint8_t> padding(length);
  for (std::size_t i = 0; i < length; ++i) {
    padding[i] = GetRandomByte();
  }
  return padding;
}

void ApplyXorTransform(
    std::uint8_t* data, const std::size_t size, const std::uint8_t key) {
  for (std::size_t i = 0; i < size; ++i) {
    data[i] ^= key;
  }
}

}  // namespace

namespace fptn::protocol::https::obfuscator {

bool TlsObfuscator2::AddData(const std::uint8_t* data, std::size_t size) {
  const std::scoped_lock<std::mutex> lock(mutex_);

  if (data && size > 0) {
    if (input_buffer_.size() + size > kMmaxBufferSize) {
      std::size_t available_space = kMmaxBufferSize - input_buffer_.size();
      if (available_space > 0) {
        input_buffer_.insert(input_buffer_.end(), data, data + available_space);
        return true;
      }
      return false;
    }
    input_buffer_.insert(input_buffer_.end(), data, data + size);
    return true;
  }
  return false;
}

PreparedData TlsObfuscator2::Deobfuscate() {
  const std::scoped_lock<std::mutex> lock(mutex_);

  if (input_buffer_.size() < sizeof(TLSAppDataRecordHeader)) {
    return std::nullopt;
  }

  std::size_t total_processed = 0;
  std::size_t search_offset = 0;
  std::vector<std::uint8_t> output;

  while (
      input_buffer_.size() - search_offset >= sizeof(TLSAppDataRecordHeader)) {
    TLSAppDataRecordHeader header = {};
    std::memcpy(&header, input_buffer_.data() + search_offset,
        sizeof(TLSAppDataRecordHeader));

    const std::uint16_t total_content_length =
        NetworkToHost16(header.content_length);
    const std::uint32_t timestamp = NetworkToHost32(header.timestamp);
    const std::uint16_t payload_length = NetworkToHost16(header.payload_length);
    const std::uint16_t padding_length = NetworkToHost16(header.padding_length);

    const bool is_fptn_protocol =
        IsValidTimestamp(timestamp) &&
        (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
        (header.headerminor == kFptnTlsApplicationHeaderMinor);

    if (!is_fptn_protocol) {
      search_offset++;
      continue;
    }

    const bool is_valid_header =
        (total_content_length >=
            sizeof(TLSAppDataRecordHeader::random_data) +
                sizeof(TLSAppDataRecordHeader::timestamp) +
                sizeof(TLSAppDataRecordHeader::xor_key) +
                sizeof(TLSAppDataRecordHeader::payload_length) +
                sizeof(TLSAppDataRecordHeader::padding_length) +
                payload_length + padding_length);

    if (!is_valid_header) {
      search_offset++;
      continue;
    }

    const size_t full_record_size =
        sizeof(TLSAppDataRecordHeader) + payload_length + padding_length;

    if (input_buffer_.size() - search_offset < full_record_size) {
      break;
    }

    const std::uint8_t* encrypted_payload =
        input_buffer_.data() + search_offset + sizeof(TLSAppDataRecordHeader);

    std::vector<std::uint8_t> decrypted_payload(
        encrypted_payload, encrypted_payload + payload_length);

    ApplyXorTransform(
        decrypted_payload.data(), decrypted_payload.size(), header.xor_key);

    output.insert(
        output.end(), decrypted_payload.begin(), decrypted_payload.end());

    input_buffer_.erase(input_buffer_.begin() + search_offset,
        input_buffer_.begin() + search_offset + full_record_size);
    total_processed += full_record_size;
    break;
  }

  if (search_offset > 0 && total_processed == 0) {
    input_buffer_.erase(
        input_buffer_.begin(), input_buffer_.begin() + search_offset);
  }
  if (!output.empty()) {
    return output;
  }
  return std::nullopt;
}

PreparedData TlsObfuscator2::Obfuscate(
    const std::uint8_t* data, std::size_t size) {
  const std::scoped_lock<std::mutex> lock(mutex_);

  const std::uint16_t padding_length = GetRandomPaddingLength();
  const std::vector<std::uint8_t> random_padding =
      GenerateRandomPadding(padding_length);

  const std::uint8_t xor_key = GetRandomByte();

  std::vector<std::uint8_t> encrypted_payload(data, data + size);
  ApplyXorTransform(
      encrypted_payload.data(), encrypted_payload.size(), xor_key);

  const std::uint16_t total_content_length =
      sizeof(TLSAppDataRecordHeader::random_data) +
      sizeof(TLSAppDataRecordHeader::timestamp) +
      sizeof(TLSAppDataRecordHeader::xor_key) +
      sizeof(TLSAppDataRecordHeader::payload_length) +
      sizeof(TLSAppDataRecordHeader::padding_length) +
      static_cast<std::uint16_t>(size) + padding_length;

  TLSAppDataRecordHeader header = {};
  header.headertype = kFptnTlsApplicationHeaderType;
  header.headermajor = kFptnTlsApplicationHeaderMajor;
  header.headerminor = kFptnTlsApplicationHeaderMinor;

  header.content_length = HostToNetwork16(total_content_length);
  header.random_data = GetRandomData();

  const std::uint32_t current_timestamp =
      fptn::time::TimeProvider::Instance()->NowTimestamp();
  header.timestamp = HostToNetwork32(current_timestamp);

  header.xor_key = xor_key;
  header.payload_length = HostToNetwork16(static_cast<std::uint16_t>(size));
  header.padding_length = HostToNetwork16(padding_length);

  std::vector<std::uint8_t> result;
  result.resize(sizeof(TLSAppDataRecordHeader) + size + padding_length);

  std::memcpy(result.data(), &header, sizeof(TLSAppDataRecordHeader));

  if (size > 0) {
    std::memcpy(result.data() + sizeof(TLSAppDataRecordHeader),
        encrypted_payload.data(), size);
  }

  if (padding_length > 0) {
    std::memcpy(result.data() + sizeof(TLSAppDataRecordHeader) + size,
        random_padding.data(), padding_length);
  }

  if (!result.empty()) {
    return result;
  }
  return std::nullopt;
}

void TlsObfuscator2::Reset() { input_buffer_.clear(); }

bool TlsObfuscator2::CheckProtocol(const std::uint8_t* data, std::size_t size) {
  const std::scoped_lock<std::mutex> lock(mutex_);

  if (data == nullptr || size < sizeof(TLSAppDataRecordHeader)) {
    return false;
  }

  TLSAppDataRecordHeader header = {};
  std::memcpy(&header, data, sizeof(TLSAppDataRecordHeader));

  const std::uint32_t timestamp = NetworkToHost32(header.timestamp);
  const std::uint16_t content_length = NetworkToHost16(header.content_length);
  const std::uint16_t payload_length = NetworkToHost16(header.payload_length);
  const std::uint16_t padding_length = NetworkToHost16(header.padding_length);

  const bool is_valid_protocol =
      (header.headertype == kFptnTlsApplicationHeaderType) &&
      (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
      (header.headerminor == kFptnTlsApplicationHeaderMinor) &&
      IsValidTimestamp(timestamp) &&
      (content_length >= sizeof(TLSAppDataRecordHeader::random_data) +
                             sizeof(TLSAppDataRecordHeader::timestamp) +
                             sizeof(TLSAppDataRecordHeader::xor_key) +
                             sizeof(TLSAppDataRecordHeader::payload_length) +
                             sizeof(TLSAppDataRecordHeader::padding_length) +
                             payload_length + padding_length) &&
      (content_length <= 16384);

  return is_valid_protocol;
}

bool TlsObfuscator2::HasPendingData() const {
  const std::scoped_lock<std::mutex> lock(mutex_);
  return !input_buffer_.empty();
}

std::shared_ptr<IObfuscator> TlsObfuscator2::Clone() const {
  return std::make_shared<TlsObfuscator2>();
}

};  // namespace fptn::protocol::https::obfuscator
