#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include "mbedtls/aes.h"

int main() {
  unsigned char cipher[16];
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, "Thats my Kung Fu", 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, "Two One Nine Two", cipher);

  uv_loop_t *loop = malloc(sizeof(uv_loop_t));
  uv_loop_init(loop);

  printf("Now quitting.\n");
  uv_run(loop, UV_RUN_DEFAULT);

  uv_loop_close(loop);
  free(loop);
  return 0;
}
