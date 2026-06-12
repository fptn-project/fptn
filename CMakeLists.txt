cmake_minimum_required(VERSION 3.16)
project(fptn VERSION "${FPTN_VERSION}" LANGUAGES CXX)

# project settings
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (APPLE)
  set(CMAKE_CXX_STANDARD 20)
else ()
  add_definitions(-DBOOST_ASIO_HAS_CO_AWAIT)
  add_definitions(-DBOOST_ASIO_HAS_CO_SPAWN)
  add_definitions(-DBOOST_ASIO_HAS_COROUTINES)
  set(CMAKE_INCLUDE_CURRENT_DIR ON)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
  endif ()
endif ()

if(MSVC)
  add_compile_options("/bigobj")
  add_compile_options("/std:c++20")
  add_compile_options("/Zc:inline-")
  add_compile_options("/permissive-")
  add_compile_options("/Zc:__cplusplus")
  add_compile_options("/d2SSAOptimizer-")
  add_compile_definitions(_WIN32_WINNT=0x0A00)  # Windows 10
endif()

# Global project definitions

if (FPTN_BUILD_ONLY_FPTN_LIB)
else()
  add_definitions(-DUSING_MIMALLOC)
  set(FPTN_WITH_LIBIDN2 ON)
  add_compile_definitions(FPTN_WITH_LIBIDN2)
endif()

add_compile_definitions(FPTN_VERSION=\"${FPTN_VERSION}\")
add_compile_definitions(FPTN_DEFAULT_MTU_SIZE=1420)
add_compile_definitions(FPTN_DEFAULT_SNI=\"rutube.ru\")
add_compile_definitions(FPTN_IP_PACKET_MAX_SIZE=1400)
add_compile_definitions(FPTN_ENABLE_PACKET_PADDING=1)
add_compile_definitions(FPTN_PROTOBUF_PROTOCOL_VERSION=0x01)
# client
add_compile_definitions(FPTN_CLIENT_DEFAULT_ADDRESS_IP6=\"fd00::1\")
add_compile_definitions(FPTN_CLIENT_DEFAULT_ADDRESS_IP4=\"10.0.0.1\")
add_compile_definitions(FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS=\"10.0.0.0/8,192.168.0.0/16\")
add_compile_definitions(FPTN_CLIENT_DEFAULT_SPLIT_TUNNEL_DOMAINS=\"domain:ru,domain:su,domain:рф,domain:vk.com,domain:yandex.com,domain:userapi.com,domain:yandex.net,domain:clstorage.net\")
add_compile_definitions(FPTN_CLIENT_DEFAULT_BLACKLIST_DOMAINS=\"domain:solovev-live.ru,domain:ria.ru,domain:tass.ru,domain:1tv.ru,domain:ntv.ru,domain:rt.com,domain:lenta.ru\")
# server
add_compile_definitions(FPTN_SERVER_DEFAULT_ADDRESS_IP6=\"fc00:1::1\")
add_compile_definitions(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6=\"fc00:1::\")
add_compile_definitions(FPTN_SERVER_DEFAULT_ADDRESS_IP4=\"172.20.0.1\")
add_compile_definitions(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4=\"172.20.0.0\")
# github
add_compile_definitions(FPTN_GITHUB_USERNAME=\"fptn-project\")
add_compile_definitions(FPTN_GITHUB_REPOSITORY=\"fptn\")
add_compile_definitions(FPTN_GITHUB_PAGE_LINK=\"https://storage.googleapis.com/fptn.org/index.html\")
# Boost
add_compile_definitions(BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS)
add_compile_definitions(BOOST_IOSTREAMS_USE_BZIP2)
add_compile_definitions(BOOST_IOSTREAMS_USE_ZLIB)
# Fix boringssl build for windows
add_definitions(-DNOMINMAX)
add_definitions(-DWIN32_LEAN_AND_MEAN)
# Minimize Windows headers and avoid NOMINMAX conflict (needed for BoringSSL)
add_definitions(-DNOMINMAX)
add_definitions(-DWIN32_LEAN_AND_MEAN)

set(FPTN_SERVER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/fptn-server")

# --- depends ---
include(depends/cmake/FetchBase64.cmake)
include(depends/cmake/NtpClient.cmake)
include(depends/cmake/CamouflageTLS.cmake)

if (NOT FPTN_BUILD_ONLY_FPTN_LIB)
    if (APPLE OR UNIX)
        include(depends/cmake/FetchLibTunTap.cmake)
    elseif (WIN32)
        include(depends/cmake/FetchWintun.cmake)
    else ()
        message(FATAL_ERROR "Unsupported platform")
    endif ()
endif ()

# --- project ---
set(CMAKE_COMPILE_WARNING_AS_ERROR ON) # check all warnings!
if (MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    add_compile_options(/W4 /WX)
else ()
    add_compile_options(-Wall -Werror -pedantic)
endif ()

# --- clang-tidy setup ---
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# search clang-tidy
find_program(
        CLANG_TIDY_EXE
        NAMES clang-tidy-22
        clang-tidy-21
        clang-tidy-20
        clang-tidy-19
        clang-tidy-18
        clang-tidy-17
        clang-tidy-16
        clang-tidy-15
        clang-tidy)
if (CLANG_TIDY_EXE)
    execute_process(
            COMMAND ${CLANG_TIDY_EXE} --version
            OUTPUT_VARIABLE CLANG_TIDY_VERSION_STRING
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "[CLANG-TIDY] clang-tidy version: ${CLANG_TIDY_VERSION_STRING}")
    if (CLANG_TIDY_VERSION_STRING MATCHES "version ([0-9]+)")
        set(CLANG_TIDY_VERSION ${CMAKE_MATCH_1})
        if (CLANG_TIDY_VERSION GREATER_EQUAL 20)
            message(STATUS "[CLANG-TIDY]  clang-tidy ${CLANG_TIDY_VERSION} accepted, enabling")
            set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-extra-arg=-std=c++20")
        else ()
            message(WARNING "[CLANG-TIDY]  clang-tidy version ${CLANG_TIDY_VERSION} is too old (<15), disabling")
        endif ()
    else ()
        message(WARNING "[CLANG-TIDY]  Could not parse clang-tidy version, disabling")
    endif ()
else ()
    message(WARNING "[CLANG-TIDY]  clang-tidy not found, skipping clang-tidy checks.")
endif ()

# --- include ---
include_directories(src/)

# --- build ---
add_subdirectory(src/fptn-protocol-lib)
if (NOT FPTN_BUILD_ONLY_FPTN_LIB)
    if (APPLE OR UNIX)
        add_subdirectory(src/fptn-server)
        add_subdirectory(src/fptn-passwd)
    endif ()
    add_subdirectory(src/fptn-client)
    # --- install ---
    install(TARGETS fptn-client-cli DESTINATION bin)
    if (APPLE OR UNIX)
        install(TARGETS fptn-server DESTINATION bin)
        install(TARGETS fptn-passwd DESTINATION bin)
    endif ()
    # --- packaging ---
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux") # deb
        add_custom_target(
                build-deb
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                COMMAND
                bash -c
                "${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-cli-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli ${FPTN_VERSION}; ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-server-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-server/fptn-server ${CMAKE_BINARY_DIR}/src/fptn-passwd/fptn-passwd ${FPTN_VERSION}"
                COMMENT "Building .deb package"
                VERBATIM)
        add_custom_target(
                build-rpm
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                COMMAND
                bash -c
                "chmod +x ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/rpm/create-server-rpm-package.sh && ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/rpm/create-server-rpm-package.sh ${CMAKE_BINARY_DIR}/src/fptn-server/fptn-server ${CMAKE_BINARY_DIR}/src/fptn-passwd/fptn-passwd ${FPTN_VERSION}"
                COMMENT "Building .rpm package"
                VERBATIM)
        if ("${FPTN_BUILD_WITH_GUI_CLIENT}")
            add_custom_target(
                    build-deb-gui
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    COMMAND
                    bash -c
                    "${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/create-client-gui-deb-package.sh ${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui ${CMAKE_CURRENT_SOURCE_DIR}/deploy/linux/deb/assets/FptnClient512x512.png ${FPTN_VERSION} ${CMAKE_CURRENT_SOURCE_DIR}/deploy/sni"
                    COMMENT "Building .deb package"
                    VERBATIM)
        endif ()
    elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin") # MacOS
        if ("${FPTN_BUILD_WITH_GUI_CLIENT}")
            add_custom_target(
                    build-pkg
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    COMMAND
                    bash -c
                    "python3 \"${CMAKE_CURRENT_SOURCE_DIR}/deploy/macos/create-pkg.py\" --fptn-client-cli=\"${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-cli\" --fptn-client-gui=\"${CMAKE_BINARY_DIR}/src/fptn-client/fptn-client-gui\" --version=\"${FPTN_VERSION}\""
                    COMMENT "Building .dmg package"
                    VERBATIM)
        endif ()
    elseif (WIN32)
        if ("${FPTN_BUILD_WITH_GUI_CLIENT}")
            add_custom_target(
                    build-installer
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    COMMAND ${CMAKE_COMMAND} -E echo "Building installer for Windows..."
                    COMMAND
                    python ${CMAKE_CURRENT_SOURCE_DIR}/deploy/windows/create-installer.py --wintun-dll=${CMAKE_BINARY_DIR}/wintun/wintun.dll
                    --fptn-client=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-gui.exe
                    --fptn-client-cli=${CMAKE_BINARY_DIR}/src/fptn-client/Release/fptn-client-cli.exe --output-folder=${CMAKE_CURRENT_SOURCE_DIR}
                    --version=${FPTN_VERSION}
                    COMMENT "Building .exe installer"
                    VERBATIM)
        endif ()
    endif ()
    # --- tests ---
    enable_testing()
    add_subdirectory(tests)
endif ()
