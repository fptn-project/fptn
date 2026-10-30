project(fptn-vless)

include(FetchContent)

# ---------------------------------------------------------------------------
# lwIP: userspace TCP/IP stack. Pinned to the release the tests were run with.
# ---------------------------------------------------------------------------
FetchContent_Declare(
  lwip
  GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
  GIT_TAG STABLE-2_2_1_RELEASE
  GIT_SHALLOW TRUE)
FetchContent_GetProperties(lwip)
if(NOT lwip_POPULATED)
  FetchContent_Populate(lwip)
endif()
set(LWIP_DIR "${lwip_SOURCE_DIR}")

add_library(
  fptn_lwip STATIC
  ${LWIP_DIR}/src/core/init.c
  ${LWIP_DIR}/src/core/def.c
  ${LWIP_DIR}/src/core/dns.c
  ${LWIP_DIR}/src/core/inet_chksum.c
  ${LWIP_DIR}/src/core/ip.c
  ${LWIP_DIR}/src/core/mem.c
  ${LWIP_DIR}/src/core/memp.c
  ${LWIP_DIR}/src/core/netif.c
  ${LWIP_DIR}/src/core/pbuf.c
  ${LWIP_DIR}/src/core/raw.c
  ${LWIP_DIR}/src/core/stats.c
  ${LWIP_DIR}/src/core/sys.c
  ${LWIP_DIR}/src/core/tcp.c
  ${LWIP_DIR}/src/core/tcp_in.c
  ${LWIP_DIR}/src/core/tcp_out.c
  ${LWIP_DIR}/src/core/timeouts.c
  ${LWIP_DIR}/src/core/udp.c
  ${LWIP_DIR}/src/core/ipv4/icmp.c
  ${LWIP_DIR}/src/core/ipv4/ip4.c
  ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
  ${LWIP_DIR}/src/core/ipv4/ip4_frag.c)
target_include_directories(
  fptn_lwip PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lwip_port"
                   "${LWIP_DIR}/src/include")
# The root project builds with -Werror/-pedantic or /WX; third-party C code is
# not subject to that.
set_target_properties(fptn_lwip PROPERTIES COMPILE_WARNING_AS_ERROR OFF)
if(MSVC)
  target_compile_options(fptn_lwip PRIVATE /W0 /WX-)
else()
  target_compile_options(fptn_lwip PRIVATE -w -Wno-error)
endif()

# ---------------------------------------------------------------------------
# fptn-vless
#
# FPTN_USERSPACE_TUN swaps the TunInterface type (see net_interface.h), so every
# translation unit that sees VpnManager::Config must be compiled WITH it. That
# is why vpn_manager.cpp & friends are compiled again here instead of being
# linked from fptn-client-cli (mixing the two would be an ODR violation).
# ---------------------------------------------------------------------------
set(FPTN_CLIENT_DIR "${CMAKE_SOURCE_DIR}/src/fptn-client")

find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem process locale)
find_package(ZLIB REQUIRED)
find_package(httplib REQUIRED)
find_package(libidn2 REQUIRED)
find_package(re2 REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(brotli REQUIRED)
find_path(BROTLI_INCLUDE_DIR "brotli/decode.h" REQUIRED)
find_library(BROTLI_DEC_LIB NAMES brotlidec REQUIRED)
find_library(BROTLI_COMMON_LIB NAMES brotlicommon REQUIRED)
find_library(BROTLI_ENC_LIB NAMES brotlienc REQUIRED)

# The exe icon (shortcut, tray, taskbar). It is drawn by a small Python script at
# configure time, so the repository (and the patch) stay text-only. Without
# Python the exe simply gets the stock icon.
set(FPTN_VLESS_RESOURCES "")
if(WIN32)
  find_program(FPTN_VLESS_PYTHON NAMES python3 python)
  if(FPTN_VLESS_PYTHON)
    set(FPTN_VLESS_ICON "${CMAKE_CURRENT_BINARY_DIR}/fptn-vless.ico")
    execute_process(
      COMMAND "${FPTN_VLESS_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/gen_icon.py"
              "${FPTN_VLESS_ICON}"
      RESULT_VARIABLE FPTN_VLESS_ICON_RESULT)
    if(FPTN_VLESS_ICON_RESULT EQUAL 0 AND EXISTS "${FPTN_VLESS_ICON}")
      set(FPTN_VLESS_RC "${CMAKE_CURRENT_BINARY_DIR}/fptn-vless.rc")
      file(WRITE "${FPTN_VLESS_RC}" "1 ICON \"${FPTN_VLESS_ICON}\"\n")
      enable_language(RC)
      set(FPTN_VLESS_RESOURCES "${FPTN_VLESS_RC}")
    else()
      message(WARNING "fptn-vless: could not draw the icon, using the default")
    endif()
  endif()
endif()

add_executable(
  "${PROJECT_NAME}"
  ${FPTN_VLESS_RESOURCES}
  fptn-vless.cpp
  app.cpp
  app.h
  platform.cpp
  platform.h
  settings_store.cpp
  settings_store.h
  tunnels.h
  dashboard.cpp
  dashboard.h
  events.h
  tunnel_check.cpp
  tunnel_check.h
  failover.cpp
  failover.h
  tunnel_manager.cpp
  tunnel_manager.h
  userspace_stack.cpp
  userspace_stack.h
  userspace_tun_device.h
  vless_server.cpp
  vless_server.h
  # shared with fptn-client-cli, recompiled with FPTN_USERSPACE_TUN
  "${FPTN_CLIENT_DIR}/vpn/vpn_manager.cpp"
  "${FPTN_CLIENT_DIR}/vpn/http/client.cpp"
  "${FPTN_CLIENT_DIR}/routing/route_manager.cpp"
  "${FPTN_CLIENT_DIR}/config/config_file.cpp"
  "${FPTN_CLIENT_DIR}/plugins/split/tunneling.cpp"
  "${FPTN_CLIENT_DIR}/utils/speed_estimator/speed_estimator.cpp")

target_compile_definitions("${PROJECT_NAME}" PRIVATE FPTN_USERSPACE_TUN=1)
if(MSVC)
  # This code was only checked with GCC/MinGW. Do not let an MSVC-only
  # warning stop the build (the root project forces /WX).
  set_target_properties("${PROJECT_NAME}" PROPERTIES COMPILE_WARNING_AS_ERROR
                                                     OFF)
  # dashboard.cpp contains the UTF-8 page
  target_compile_options("${PROJECT_NAME}" PRIVATE /WX- /utf-8)
endif()
# fptn-client sources include each other relative to src/fptn-client
target_include_directories("${PROJECT_NAME}" PRIVATE "${FPTN_CLIENT_DIR}"
                                                     "${BROTLI_INCLUDE_DIR}")

if(WIN32)
  # no Wintun here on purpose: this program never creates an adapter
  set(PLATFORM_LIBS rpcrt4 iphlpapi Kernel32.lib ws2_32 user32 shell32 ole32
                    uuid crypt32 advapi32)
else()
  set(PLATFORM_LIBS "")
endif()

target_link_libraries(
  "${PROJECT_NAME}"
  PRIVATE fptn_lwip
          ZLIB::ZLIB
          Boost::boost
          Boost::random
          Boost::filesystem
          Boost::process
          Boost::locale
          OpenSSL::SSL
          OpenSSL::Crypto
          argparse::argparse
          nlohmann_json::nlohmann_json
          spdlog::spdlog
          fmt::fmt
          libidn2::libidn2
          re2::re2
          fptn-protocol-lib_static
          "${BROTLI_DEC_LIB}"
          "${BROTLI_COMMON_LIB}"
          ${PLATFORM_LIBS})

install(TARGETS "${PROJECT_NAME}" DESTINATION bin)

# --- tests (no FPTN server needed) -----------------------------------------
option(FPTN_VLESS_BUILD_TESTS "Build the fptn-vless loopback test" ON)
if(FPTN_VLESS_BUILD_TESTS AND UNIX)
  add_executable(fptn_vless_echo_peer test/echo_peer.cpp)
  target_link_libraries(fptn_vless_echo_peer PRIVATE fptn_lwip)

  add_executable(fptn_vless_loopback_test test/loopback_test.cpp
                                          userspace_stack.cpp vless_server.cpp tunnel_check.cpp)
  target_link_libraries(
    fptn_vless_loopback_test PRIVATE fptn_lwip spdlog::spdlog fmt::fmt
                                     Boost::boost)
  add_executable(fptn_vless_failover_test test/failover_test.cpp failover.cpp)
  target_link_libraries(fptn_vless_failover_test PRIVATE spdlog::spdlog
                                                         fmt::fmt)
  add_test(NAME fptn_vless_failover COMMAND fptn_vless_failover_test)

  add_executable(fptn_vless_dashboard_test test/dashboard_test.cpp dashboard.cpp)
  target_link_libraries(fptn_vless_dashboard_test PRIVATE spdlog::spdlog
                                                          fmt::fmt Boost::boost)
  add_test(NAME fptn_vless_dashboard COMMAND fptn_vless_dashboard_test)

  add_executable(
    fptn_vless_app_test test/app_test.cpp app.cpp failover.cpp settings_store.cpp
                        userspace_stack.cpp vless_server.cpp)
  target_link_libraries(
    fptn_vless_app_test PRIVATE fptn_lwip spdlog::spdlog fmt::fmt Boost::boost
                                OpenSSL::Crypto nlohmann_json::nlohmann_json)
  add_test(NAME fptn_vless_app COMMAND fptn_vless_app_test)
  add_test(NAME fptn_vless_loopback
           COMMAND fptn_vless_loopback_test
           WORKING_DIRECTORY $<TARGET_FILE_DIR:fptn_vless_echo_peer>)
endif()
