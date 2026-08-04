if(NOT EXISTS "${GZ}")
  set(SOURCES
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt"
      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  )

  set(combined "${GZ}.txt")
  file(WRITE "${combined}" "")

  set(any_success FALSE)
  foreach(src IN LISTS SOURCES)
    set(part "${GZ}.part")
    message(STATUS "[blocklist] downloading ${src}")
    file(DOWNLOAD "${src}" "${part}" STATUS status TLS_VERIFY ON)
    list(GET status 0 code)
    if(code EQUAL 0)
      file(READ "${part}" content)
      file(APPEND "${combined}" "${content}")
      set(any_success TRUE)
    else()
      list(GET status 1 msg)
      message(WARNING "[blocklist] failed ${src}: ${msg}")
    endif()
    file(REMOVE "${part}")
  endforeach()

  if(NOT any_success)
    file(REMOVE "${combined}")
    message(FATAL_ERROR "[blocklist] all sources failed")
  endif()

  file(ARCHIVE_CREATE OUTPUT "${GZ}" PATHS "${combined}"
       FORMAT raw COMPRESSION GZip)
  file(REMOVE "${combined}")
  message(STATUS "[blocklist] saved ${GZ}")
endif()

file(READ "${GZ}" hex HEX)
string(LENGTH "${hex}" hex_len)
math(EXPR num_bytes "${hex_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")

file(WRITE "${OUTPUT}"
"namespace fptn::adblock {
extern const unsigned char ${SYMBOL}[] = {
${bytes}
};
extern const unsigned int ${SYMBOL}Len = ${num_bytes}u;
}  // namespace fptn::adblock
")
