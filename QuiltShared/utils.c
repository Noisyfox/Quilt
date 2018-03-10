#include <string.h>
#include <stdio.h>

#include "utils.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

int doSHA256(const unsigned char *input, size_t ilen, unsigned char output[32])
{
	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);

	int rv = mbedtls_sha256_starts_ret(&sha, 0);
	if (rv)
	{
		goto finish;
	}
	rv = mbedtls_sha256_update_ret(&sha, input, ilen);
	if (rv)
	{
		goto finish;
	}
	rv = mbedtls_sha256_finish_ret(&sha, output);

finish:
	mbedtls_sha256_free(&sha);
	return rv;
}

int doAES(int mode, const unsigned char iv[16], const unsigned char key[32], const unsigned char *input, size_t ilen, unsigned char *output)
{
	size_t iv_off = 0;
	unsigned char _iv[16];
	memcpy(_iv, iv, 16);

	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	int rv = mbedtls_aes_setkey_enc(&aes, key, 256);
	if (rv)
	{
		goto finish;
	}
	rv = mbedtls_aes_crypt_cfb128(&aes, mode, ilen, &iv_off, _iv, input, output);

finish:
	mbedtls_aes_free(&aes);
	return rv;
}

// Generate pseudo-random based on https://github.com/cbeuw/GoQuiet/wiki/GoQuiet#%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86
int calculate_random(const unsigned char iv[16], const char* psk, const long timestamp, unsigned char output[16])
{
	unsigned char key[32];
	unsigned char rest[32];
	char goal[1024];

	int rv;

	if ((rv = doSHA256((const unsigned char *)psk, strlen(psk), key)))
	{
		return rv;
	}

	// Generate goal
	sprintf_s(goal, 1024, "%ld%s", timestamp, psk); // Here we allow 1 hour difference
	if ((rv = doSHA256((const unsigned char *)goal, strlen(goal), rest)))
	{
		return rv;
	}

	rv = doAES(MBEDTLS_AES_ENCRYPT, iv, key, rest, 16, output);
	return rv;
}
