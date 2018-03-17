#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "utils.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "tls.h"

const char* progname = NULL;
int verbose = 0;

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
	snprintf(goal, sizeof goal, "%ld%s", timestamp, psk); // Here we allow 1 hour difference
	if ((rv = doSHA256((const unsigned char *)goal, strlen(goal), rest)))
	{
		return rv;
	}

	rv = doAES(MBEDTLS_AES_ENCRYPT, iv, key, rest, 16, output);
	return rv;
}

#define DEBUG_BUF_SIZE      512

// Copy from mbedtls/debug.c
void debug_print_msg(const char *file, int line, const char *format, ...)
{
	va_list argp;
	char str[DEBUG_BUF_SIZE];
	int ret;

	va_start(argp, format);
#if defined(_WIN32)
#if defined(_TRUNCATE)
	ret = _vsnprintf_s(str, DEBUG_BUF_SIZE, _TRUNCATE, format, argp);
#else
	ret = _vsnprintf(str, DEBUG_BUF_SIZE, format, argp);
	if (ret < 0 || (size_t)ret == DEBUG_BUF_SIZE)
	{
		str[DEBUG_BUF_SIZE - 1] = '\0';
		ret = -1;
	}
#endif
#else
	ret = vsnprintf(str, DEBUG_BUF_SIZE, format, argp);
#endif
	va_end(argp);

	if (ret >= 0 && ret < DEBUG_BUF_SIZE - 1)
	{
		str[ret] = '\n';
		str[ret + 1] = '\0';
	}

	fputs(str, stderr);
}

// Copy from mbedtls/debug.c
void debug_print_buf(const char *file, int line, const char *text, const unsigned char *buf, size_t len)
{
	char str[DEBUG_BUF_SIZE];
	char txt[17];
	size_t i, idx = 0;

	snprintf(str + idx, sizeof(str) - idx, "dumping '%s' (%u bytes)\n",
		text, (unsigned int)len);

	fputs(str, stderr);

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
				fputs(str, stderr);

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
		fputs(str, stderr);
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
		return UV_EINVAL;
	}

	void** handle_data = malloc(sizeof(void*) * req->handle_count);
	if (!handle_data)
	{
		return UV_ENOMEM;
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
	int free_buf;
} write_req_t;

int uv_ext_write(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, uv_write_cb cb)
{
	unsigned char* b = malloc(sizeof(unsigned char) * buf_len);
	if (!b)
	{
		return UV_ENOMEM;
	}
	memcpy(b, buf, buf_len);

	int rv = uv_ext_write2(handle, b, buf_len, data, 1, cb);
	if (rv)
	{
		free(b);
	}

	return rv;
}

int uv_ext_write2(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, int free_after_write, uv_write_cb cb)
{
	write_req_t* rq = (write_req_t*)malloc(sizeof(write_req_t));
	if (!rq)
	{
		return UV_ENOMEM;
	}

	rq->free_buf = free_after_write;
	rq->buf.base = (char*)buf;
	rq->buf.len = buf_len;
	rq->req.data = data;

	int rv = uv_write(&rq->req, handle, &rq->buf, 1, cb);
	if (rv)
	{
		free(rq);
		return rv;
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

/*
 * Send data as much as possible, within full tls records
 */
int uv_write_tls_application_data_full(uv_stream_t* handle, int v_major, int v_minor, buffer* raw_data, uv_write_cb cb)
{
	unsigned char* buf;
	while ((buf = buffer_raw_header(raw_data, Q_MAX_TLS_RECORD_LENGTH)))
	{
		unsigned char* obuf;
		size_t olen;

		int rv = tls_wrap_application_data(v_major, v_minor, buf, Q_MAX_TLS_RECORD_LENGTH, &obuf, &olen);
		if (rv)
		{
			return rv;
		}

		rv = uv_ext_write2(handle, obuf, olen, NULL, 1, cb);
		if (rv)
		{
			free(obuf);
			return rv;
		}

		if (buffer_pop(raw_data, Q_MAX_TLS_RECORD_LENGTH) != Q_MAX_TLS_RECORD_LENGTH)
		{
			return UV_UNKNOWN;
		}
	}

	return 0;
}

/*
 * Send all remain data
 */
int uv_write_tls_application_data_all(uv_stream_t* handle, int v_major, int v_minor, buffer* raw_data, uv_write_cb cb)
{
	int rv = uv_write_tls_application_data_full(handle, v_major, v_minor, raw_data, cb);
	if (rv)
	{
		return rv;
	}

	size_t remain = buffer_available(raw_data);
	if (!remain)
	{
		return 0;
	}

	unsigned char* buf = buffer_raw_header(raw_data, remain);
	if (!buf)
	{
		return UV_UNKNOWN;
	}

	unsigned char* obuf;
	size_t olen;

	rv = tls_wrap_application_data(v_major, v_minor, buf, remain, &obuf, &olen);
	if (rv)
	{
		return rv;
	}

	rv = uv_ext_write2(handle, obuf, olen, NULL, 1, cb);
	if (rv)
	{
		free(obuf);
		return rv;
	}

	if (buffer_pop(raw_data, remain) != remain)
	{
		return UV_UNKNOWN;
	}

	return 0;
}

int parse_int(const char* in, int* out, int radix)
{
	char* end;
	int v = strtol(in, &end, radix);

	if(end == in || end != in + strlen(in))
	{
		return -1;
	}

	*out = v;
	
	return 0;
}
