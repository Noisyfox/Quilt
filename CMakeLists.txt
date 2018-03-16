cmake_minimum_required(VERSION 3.0)
project(Quilt)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(USE_SYSTEM_LIBRARY "Build Quilt with system's library" OFF)

if (USE_SYSTEM_LIBRARY)
  find_package(Libuv)     # -> uv
  find_package(MbedTLS)   # -> mbedtls mbedx509 mbedcrypto

  if (NOT LIBUV_FOUND)
    message(FATAL_ERROR "libuv not found")
  endif()
  if (NOT MBEDTLS_FOUND)
    message(FATAL_ERROR "mbedtls not found")
  endif()
else()
  # libuv
  message(STATUS "Using submodule libuv")
  add_subdirectory(${CMAKE_SOURCE_DIR}/cmake/uv)
  # mbedtls
  message(STATUS "Using submodule mbedtls")
  set(ENABLE_PROGRAMS OFF CACHE BOOL "not Build mbed TLS programs." FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "not Build mbed TLS tests." FORCE)
  add_subdirectory(${CMAKE_SOURCE_DIR}/mbedtls)
  include_directories(${CMAKE_SOURCE_DIR}/mbedtls/include/)
endif()

# https://stackoverflow.com/a/30564223
macro(use_c99)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set(CMAKE_C_FLAGS "-std=gnu99 ${CMAKE_C_FLAGS}")
    endif()
  else()
    set(CMAKE_C_STANDARD 99)
  endif()
endmacro(use_c99)

add_subdirectory(${CMAKE_SOURCE_DIR}/QuiltShared)   # -> quilt_shared

add_subdirectory(${CMAKE_SOURCE_DIR}/QuiltServer)
add_subdirectory(${CMAKE_SOURCE_DIR}/Quilt)

# add_executable(craft craft.c)
# target_link_libraries(craft uv mbedcrypto)
