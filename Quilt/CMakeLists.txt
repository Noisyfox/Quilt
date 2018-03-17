use_c99()

set(SOURCES
  bio.c
  bio.h
  main.cpp
  tls_engine.c
  tls_engine.h
  uv_tls.c
  uv_tls.h
  config.c
  config.h
)

add_executable(Quilt ${SOURCES})
target_link_libraries(Quilt quilt_shared uv mbedtls mbedx509 mbedcrypto)
