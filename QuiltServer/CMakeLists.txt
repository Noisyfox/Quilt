use_c99()

set(SOURCES
  main.cpp
  config.c
  config.h
)

add_executable(QuiltServer ${SOURCES})
target_link_libraries(QuiltServer quilt_shared uv mbedtls mbedx509 mbedcrypto)
