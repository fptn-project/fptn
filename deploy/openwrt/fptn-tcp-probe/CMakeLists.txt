project(fptn-tcp-probe)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(argparse REQUIRED)

add_executable("${PROJECT_NAME}" fptn-tcp-probe.cpp)

target_link_libraries("${PROJECT_NAME}" PRIVATE argparse::argparse)
