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

add_executable(netguard_tests test_sanity.cpp)
target_link_libraries(netguard_tests PRIVATE netguard_warnings GTest::gtest_main)
gtest_discover_tests(netguard_tests)
