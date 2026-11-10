cmake_minimum_required(VERSION 3.16)
project(netguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(NETGUARD_BUILD_TESTS "Build the GoogleTest suite" ON)
option(NETGUARD_WERROR "Treat compiler warnings as errors" OFF)
option(NETGUARD_SANITIZE "Build with AddressSanitizer + UBSan" OFF)

# Warning flags shared by every target we own (not by third-party code).
add_library(netguard_warnings INTERFACE)
target_compile_options(netguard_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  $<$<BOOL:${NETGUARD_WERROR}>:-Werror>)

if(NETGUARD_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

add_executable(netguard-cli src/main.cpp)
target_link_libraries(netguard-cli PRIVATE netguard_warnings)

if(NETGUARD_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
