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

#define DEBUG_BUF_SIZE      512

void debug_print_buf(const char *file, int line, const char *text, const unsigned char *buf, size_t len)
{
	char str[DEBUG_BUF_SIZE];
	char txt[17];
	size_t i, idx = 0;

	snprintf(str + idx, sizeof(str) - idx, "dumping '%s' (%u bytes)\n",
		text, (unsigned int)len);

	fprintf(stderr, str);

	idx = 0;
	memset(txt, 0, sizeof(txt));
	for (i = 0; i < len; i++)
	{
		if (i >= 4096)
			break;

		if (i % 16 == 0)
		{
			if (i > 0)
			{
				snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
				fprintf(stderr, str);

				idx = 0;
				memset(txt, 0, sizeof(txt));
			}

			idx += snprintf(str + idx, sizeof(str) - idx, "%04x: ",
				(unsigned int)i);

		}

		idx += snprintf(str + idx, sizeof(str) - idx, " %02x",
			(unsigned int)buf[i]);
		txt[i % 16] = (buf[i] > 31 && buf[i] < 127) ? buf[i] : '.';
	}

	if (len > 0)
	{
		for ( /* i = i */; i % 16 != 0; i++)
			idx += snprintf(str + idx, sizeof(str) - idx, "   ");

		snprintf(str + idx, sizeof(str) - idx, "  %s\n", txt);
		fprintf(stderr, str);
	}
}

static void on_close(uv_handle_t* peer) {
	uv_ext_close_t* req = peer->data;
	
	for (size_t i = 0; i < req->handle_count; i++)
	{
		uv_handle_t* h = req->handles[i];
		if(peer == h)
		{
			req->handle_closed |= 1LL << i;
			h->data = req->handle_data[i];
		}
	}

	if (req->handle_closed + 1 == 1LL << req->handle_count)
	{
		free(req->handle_data);
		req->close_cb(req);
	}
}

int uv_ext_close(uv_ext_close_t* req, uv_ext_close_cb cb)
{
	if(req->handle_count == 0)
	{
		cb(req);
		return 0;
	}

	if (req->handle_count > 64)
	{
		return -1;
	}

	void** handle_data = malloc(sizeof(void*) * req->handle_count);
	if (!handle_data)
	{
		return -1;
	}

	req->handle_closed = 0;
	req->close_cb = cb;
	req->handle_data = handle_data;

	for (size_t i = 0; i < req->handle_count; i++)
	{
		uv_handle_t* h = req->handles[i];

		if (uv_is_closing(h))
		{
			req->handle_closed |= 1LL << i;
		}
		else {
			handle_data[i] = h->data;
			h->data = req;
			uv_close(h, on_close);
		}
	}
	if(req->handle_closed + 1 == 1LL << req->handle_count)
	{
		free(req->handle_data);
		cb(req);
	}

	return 0;
}


typedef struct {
	uv_write_t req;
	uv_buf_t buf;
	BOOL free_buf;
} write_req_t;

int uv_ext_write(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, uv_write_cb cb)
{
	unsigned char* b = malloc(sizeof(unsigned char) * buf_len);
	if (!b)
	{
		return -1;
	}
	memcpy(b, buf, buf_len);

	int rv = uv_ext_write2(handle, b, buf_len, data, TRUE, cb);
	if (rv)
	{
		free(b);
	}

	return rv;
}

int uv_ext_write2(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, BOOL free_after_write, uv_write_cb cb)
{
	write_req_t* rq = (write_req_t*)malloc(sizeof(write_req_t));
	if (!rq)
	{
		return -1;
	}

	rq->free_buf = free_after_write;
	rq->buf.base = buf;
	rq->buf.len = buf_len;
	rq->req.data = data;

	if (uv_write(&rq->req, handle, &rq->buf, 1, cb))
	{
		free(rq);
		return -1;
	}

	return 0;
}

void* uv_ext_write_cleanup(uv_write_t* req)
{
	void* data = req->data;

	write_req_t* rq = (write_req_t*)req;
	if (rq->free_buf) {
		free(rq->buf.base);
	}
	free(rq);

	return data;
}
