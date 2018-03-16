use_c99()

set(SOURCES
  simple_buffer.h
  simple_buffer.c
  tls.c
  tls.h
  utils.c
  utils.h
  getopt.c
  getopt.h
  json.c
  json.h
)

add_library(quilt_shared STATIC ${SOURCES})
target_link_libraries(quilt_shared uv mbedtls mbedx509 mbedcrypto)
target_include_directories(quilt_shared PUBLIC .)
