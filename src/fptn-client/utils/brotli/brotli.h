/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include <brotli/decode.h>  // NOLINT(build/include_order)

namespace fptn::utils::brotli {
inline std::string Decompress(const std::string& compressed_data) {
  const std::size_t encoded_size = compressed_data.size();
  std::size_t decoded_size = encoded_size * 30;

  while (true) {
    std::vector<std::uint8_t> decoded_buffer(decoded_size);
    std::size_t available_out = decoded_size;

    const BrotliDecoderResult result = BrotliDecoderDecompress(encoded_size,
        reinterpret_cast<const uint8_t*>(compressed_data.data()),
        &available_out, decoded_buffer.data());
    if (result == BROTLI_DECODER_RESULT_SUCCESS) {
      return std::string(
          reinterpret_cast<char*>(decoded_buffer.data()), available_out);
    }
    if (result != BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      // A corrupt or truncated stream never becomes decodable by growing the
      // buffer; without this check the loop doubles it until the OOM killer
      // reaps the whole client.
      throw std::runtime_error("Brotli decompression failed: corrupt stream");
    }
    decoded_size *= 2;
  }
}
}  // namespace fptn::utils::brotli
