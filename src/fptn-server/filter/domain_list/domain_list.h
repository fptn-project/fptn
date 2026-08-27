/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace fptn::filter::domain_list {

/**
 * @brief Domain lists a filter blocks, downloaded from @p urls and kept in
 * @p cache_dir.
 *
 * The directory is created if it does not exist and every URL gets its own
 * file there. A file that is missing or older than an hour is downloaded
 * again: first into a temporary file, and only a complete download replaces
 * the cached one. A failed download keeps the previous copy, so the server
 * always starts with whatever it had.
 */
std::vector<std::string> Load(const std::filesystem::path& cache_dir,
    const std::vector<std::string>& urls);

}  // namespace fptn::filter::domain_list
