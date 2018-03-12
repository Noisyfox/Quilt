#ifndef Q_UTILS_H
#define Q_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#define FREE(p) \
	do { \
	    if(p)free(p); \
    } while(0)


#define Q_DEBUG_BUF( text, buf, len )           \
    debug_print_buf( __FILE__, __LINE__, text, buf, len )

	int doSHA256(const unsigned char *input, size_t ilen, unsigned char output[32]);
	int doAES(int mode, const unsigned char iv[16], const unsigned char key[32], const unsigned char *input, size_t ilen, unsigned char *output);
	int calculate_random(const unsigned char iv[16], const char* psk, long timestamp, unsigned char output[16]);


	void debug_print_buf(const char *file, int line, const char *text, const unsigned char *buf, size_t len);

#ifdef __cplusplus
};
#endif

#endif //Q_UTILS_H
