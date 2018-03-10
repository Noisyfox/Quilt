#include <string.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "tls.h"

int tls_peek_next_record(buffer* buf, tls_record* out)
{
	unsigned char* b = buffer_raw_header(buf, 5);
	if (!b)
	{
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	int major, minor;
	mbedtls_ssl_read_version(&major, &minor, MBEDTLS_SSL_TRANSPORT_STREAM, b + 1);

	if (major < MBEDTLS_SSL_MAJOR_VERSION_3)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	unsigned char * buf_len = b + 3;
	size_t msg_len = (buf_len[0] << 8) | buf_len[1];

	if (msg_len > MBEDTLS_SSL_MAX_CONTENT_LEN)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	b = buffer_raw_header(buf, 5 + msg_len);
	if (!b)
	{
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	out->msg_type = b[0];
	out->major_ver = major;
	out->minor_ver = minor;
	out->msg_len = msg_len;
	out->buf = b;
	out->buf_hdr = b;
	out->buf_len = buf_len;
	out->buf_msg = buf_len + 2;

	return 0;
}

int tls_pop_record(buffer* buf, tls_record* r)
{
	unsigned char* b = buffer_raw_header(buf, 5 + r->msg_len);
	if (!b)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}
	if (b != r->buf)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	if (buffer_pop(buf, 5 + r->msg_len) != 5 + r->msg_len)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	memset(r, 0, sizeof(tls_record));

	return 0;
}

int tls_extract_handshake(tls_record* record, size_t offset, tls_handshake* out, size_t* next_offset)
{
	if (record->msg_type != MBEDTLS_SSL_MSG_HANDSHAKE)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	if (record->msg_len < offset)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	size_t remain_len = record->msg_len - offset;
	if (remain_len < 4)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	unsigned char* b = record->buf_msg + offset;
	int msg_type = b[0];
	size_t msg_len = (b[1] << 16) | (b[2] << 8) | b[3];
	if (remain_len < 4 + msg_len)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	out->record = record;
	out->record_msg_offset = offset;
	out->msg_type = msg_type;
	out->msg_len = msg_len;
	out->buf = b;
	out->buf_hdr = b;
	out->buf_len = b + 1;
	out->buf_msg = out->buf_len + 3;

	if (next_offset) {
		*next_offset = offset + 4 + msg_len;
	}

	return 0;
}
