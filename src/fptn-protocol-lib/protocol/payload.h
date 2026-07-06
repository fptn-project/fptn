/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#ifdef USING_MIMALLOC
#include <mimalloc.h>  // NOLINT(build/include_order)
#endif

namespace fptn::protocol {

#ifdef USING_MIMALLOC
using ProtoPayload = std::vector<std::uint8_t, mi_stl_allocator<std::uint8_t>>;
using ProtoPayloadOpt = std::optional<ProtoPayload>;
using BatchProtoPayload = std::vector<ProtoPayload,
mi_stl_allocator<ProtoPayload>>;  // NOLINT
#else
using ProtoPayload = std::vector<std::uint8_t>;
using ProtoPayloadOpt = std::optional<ProtoPayload>;
using BatchProtoPayload = std::vector<ProtoPayload>;
#endif

}  // namespace fptn::protocol
