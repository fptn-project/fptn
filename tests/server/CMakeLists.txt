find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(prometheus-cpp REQUIRED)

if(WIN32)
  set(TUNTAP_LIB Wintun rpcrt4)
else()
  set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    fptn-protocol-lib_static
    prometheus-cpp::prometheus-cpp
    ${TUNTAP_LIB})

include_directories(${FPTN_SERVER_PATH})

# --- MetricTest test ---
add_executable(MetricTest statistic/MetricTest.cpp ${FPTN_SERVER_PATH}/statistic/metrics.h ${FPTN_SERVER_PATH}/statistic/metrics.cpp)
target_link_libraries(MetricTest PRIVATE ${LIBS})
add_test(NAME MetricTest COMMAND MetricTest)

# --- AntiScan test ---
add_executable(AntiScanTest filter/antiscan/AntiScanTest.cpp ${FPTN_SERVER_PATH}/filter/filters/antiscan/antiscan.h
                            ${FPTN_SERVER_PATH}/filter/filters/antiscan/antiscan.cpp)
target_link_libraries(AntiScanTest PRIVATE ${LIBS})
add_test(NAME AntiScanTest COMMAND AntiScanTest)
