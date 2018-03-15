#ifndef Q_TLS_H
#define Q_TLS_H

#include "simple_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct
	{
		int msg_type;
		int major_ver;
		int minor_ver;
		size_t msg_len;

		unsigned char *buf;
		unsigned char *buf_hdr;      /*!< start of record header           */
		unsigned char *buf_len;      /*!< two-bytes message length field   */
		unsigned char *buf_msg;      /*!< message contents (in_iv+ivlen)   */
	} tls_record;

	typedef struct
	{
		tls_record* record;
		size_t record_msg_offset; // Offset based on record->buf_msg

		int msg_type;
		size_t msg_len;

		unsigned char *buf;
		unsigned char *buf_hdr;      /*!< start of message header           */
		unsigned char *buf_len;      /*!< three-bytes message length field   */
		unsigned char *buf_msg;      /*!< message contents (in_iv+ivlen)   */
	} tls_handshake;

	int tls_peek_next_record(buffer* buf, tls_record* out);
	int tls_pop_record(buffer* buf, tls_record* r);

	int tls_extract_handshake(tls_record* record, size_t offset, tls_handshake* out, size_t* next_offset);

	int tls_wrap_application_data(int v_major, int v_minor, const unsigned char* data, size_t ilen, unsigned char** output, size_t* olen);

#define Q_MAX_TLS_RECORD_LENGTH 16408

#ifdef __cplusplus
};
#endif

#endif //Q_TLS_H
