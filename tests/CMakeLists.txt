# Prefer the system GoogleTest (Arch: gtest, Ubuntu: libgtest-dev); fall back to downloading it.
find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()
include(GoogleTest)

add_executable(netguard_tests
  test_byte_view.cpp
  test_decode.cpp
  test_pcap_reader.cpp
  test_samples.cpp)
target_link_libraries(netguard_tests PRIVATE netguard_core netguard_warnings GTest::gtest_main)
target_compile_definitions(netguard_tests PRIVATE
  NETGUARD_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
gtest_discover_tests(netguard_tests)

# Week-1 exit check as a test: netguard-cli must agree with tcpdump -nn on every sample.
option(NETGUARD_REQUIRE_TCPDUMP "Fail configuration if tcpdump is missing" OFF)
find_program(TCPDUMP_EXECUTABLE tcpdump PATHS /usr/sbin /sbin)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(TCPDUMP_EXECUTABLE AND Python3_Interpreter_FOUND)
  file(GLOB NETGUARD_SAMPLE_PCAPS "${CMAKE_CURRENT_SOURCE_DIR}/data/*.pcap")
  add_test(NAME tcpdump_comparison
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/compare_tcpdump.py
      --cli $<TARGET_FILE:netguard-cli> --tcpdump ${TCPDUMP_EXECUTABLE} ${NETGUARD_SAMPLE_PCAPS})
elseif(NETGUARD_REQUIRE_TCPDUMP)
  message(FATAL_ERROR "tcpdump (and python3) are required for the tcpdump_comparison test")
else()
  message(STATUS "tcpdump not found: skipping tcpdump_comparison test")
endif()
