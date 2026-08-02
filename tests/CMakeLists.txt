find_package(GTest REQUIRED)

add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(fptnlib)
add_subdirectory(fptn-client)

add_custom_target(
  run_tests
  COMMAND ${CMAKE_CTEST_COMMAND}
  DEPENDS tests_common common
  COMMENT "Running all tests"
  VERBATIM)
