cmake_minimum_required(VERSION 3.20)
project(wirebone VERSION 0.1.0 LANGUAGES CXX)

set(WIREBONE_IS_TOPLEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(WIREBONE_IS_TOPLEVEL ON)
endif()

option(WIREBONE_BUILD_CLI "Build the wirebone CLI" ${WIREBONE_IS_TOPLEVEL})
option(WIREBONE_BUILD_TESTS "Build wirebone unit tests" ${WIREBONE_IS_TOPLEVEL})

if(WIREBONE_IS_TOPLEVEL)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET libcrypto)
pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)

include(FetchContent)
if(NOT TARGET nlohmann_json::nlohmann_json)
  FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

add_library(wirebone
  src/crypto.cpp
  src/keys.cpp
  src/noise.cpp
  src/ip_alloc.cpp
  src/state.cpp
  src/http1.cpp
  src/http2_session.cpp
  src/netmap.cpp
  src/dns.cpp
  src/coordinator.cpp
  src/c_api.cpp
)

set_target_properties(wirebone PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
)

target_include_directories(wirebone
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# PUBLIC so static consumers (QuackScale) pull in the link line.
target_link_libraries(wirebone
  PUBLIC
    nlohmann_json::nlohmann_json
    PkgConfig::OPENSSL
    PkgConfig::NGHTTP2
    PkgConfig::ZSTD
)

target_compile_options(wirebone PRIVATE -Wall -Wextra -Wpedantic)

if(APPLE)
  target_compile_definitions(wirebone PRIVATE WIREBONE_MACOS=1)
endif()

if(WIREBONE_BUILD_CLI)
  add_executable(wirebone_cli src/main.cpp)
  set_target_properties(wirebone_cli PROPERTIES
    OUTPUT_NAME wirebone
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  target_link_libraries(wirebone_cli PRIVATE wirebone)
  target_include_directories(wirebone_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

if(WIREBONE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
