# Generates a header with the default split-tunnel domain list.
#   -DINPUT=<domain list>  -DOUTPUT=<header>  -DBASE=<comma separated domains>

set(domains "")

string(REPLACE "," ";" base_list "${BASE}")
foreach(domain IN LISTS base_list)
  string(STRIP "${domain}" domain)
  if(NOT domain STREQUAL "")
    list(APPEND domains "${domain}")
  endif()
endforeach()

file(READ "${INPUT}" content)
string(REPLACE "\r\n" "\n" content "${content}")
string(REPLACE ";" "" content "${content}")
string(REPLACE "\n" ";" lines "${content}")
foreach(line IN LISTS lines)
  string(REGEX REPLACE "#.*$" "" line "${line}")
  string(STRIP "${line}" line)
  string(TOLOWER "${line}" line)
  string(REGEX REPLACE "^domain:" "" line "${line}")
  string(REGEX REPLACE "\\.$" "" line "${line}")
  if(NOT line STREQUAL "")
    list(APPEND domains "${line}")
  endif()
endforeach()

list(REMOVE_DUPLICATES domains)
list(LENGTH domains total)

set(items "")
foreach(domain IN LISTS domains)
  string(APPEND items "    \"${domain}\",\n")
endforeach()

file(WRITE "${OUTPUT}"
"// Generated from ${INPUT} - do not edit.
#pragma once

#include <string_view>

namespace fptn::defaults {
inline constexpr std::string_view kSplitTunnelDomains[] = {
${items}};
}  // namespace fptn::defaults
")
message(STATUS "[split-tunnel] embedded ${total} default domains")
