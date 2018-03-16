#ifndef Q_UTILS_H
#define Q_UTILS_H

#ifndef _WIN32
// TODO: replace with non-Windows specific stuffs
#ifndef BOOL
#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#endif

#include "uv.h"
#include "simple_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

	extern int verbose;

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define FLAG_TEST(v, f) (((v) & (f)) == (f))
#define FLAG_SET(v, f) ((v) = ((v) | (f)))

#define DEFAULT_BACKLOG 10

#define FREE(p) \
	do { \
	    if(p)free(p); \
    } while(0)


#define Q_DEBUG_BUF( text, buf, len )           \
	if(verbose) \
		debug_print_buf( __FILE__, __LINE__, text, buf, len )

#define Q_DEBUG_MSG( ... )                    \
	if(verbose) \
		debug_print_msg( __FILE__, __LINE__, __VA_ARGS__ )

	int doSHA256(const unsigned char *input, size_t ilen, unsigned char output[32]);
	int doAES(int mode, const unsigned char iv[16], const unsigned char key[32], const unsigned char *input, size_t ilen, unsigned char *output);
	int calculate_random(const unsigned char iv[16], const char* psk, long timestamp, unsigned char output[16]);

	void debug_print_msg(const char *file, int line, const char *format, ...);
	void debug_print_buf(const char *file, int line, const char *text, const unsigned char *buf, size_t len);


	typedef struct uv_ext_close_s uv_ext_close_t;

	typedef void(*uv_ext_close_cb)(uv_ext_close_t* req);

	struct uv_ext_close_s
	{
		void* data;
		uv_handle_t** handles;
		size_t handle_count;

		// Private fields:
		uv_ext_close_cb close_cb;
		uint64_t handle_closed;
		void** handle_data;
	};

	int uv_ext_close(uv_ext_close_t* req, uv_ext_close_cb cb);
	int uv_ext_write(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, uv_write_cb cb);
	// None-copy version of uv_ext_write, re-use the buffer you given
	int uv_ext_write2(uv_stream_t* handle, const unsigned char* buf, size_t buf_len, void* data, BOOL free_after_write, uv_write_cb cb);
	void* uv_ext_write_cleanup(uv_write_t* req);

	int uv_write_tls_application_data_full(uv_stream_t* handle, int v_major, int v_minor, buffer* raw_data, uv_write_cb cb);
	int uv_write_tls_application_data_all(uv_stream_t* handle, int v_major, int v_minor, buffer* raw_data, uv_write_cb cb);

#if !((defined(__STDC_LIB_EXT1__) && __STDC_WANT_LIB_EXT1__) || defined(_MSC_VER))
	static inline int strcpy_s(char * dest, rsize_t destsz, const char * src)
	{
		return snprintf(dest, destsz, "%s", src);
	}
#endif

	int parse_int(const char* in, int* out, int radix);

#ifdef __cplusplus
};
#endif

#endif //Q_UTILS_H
