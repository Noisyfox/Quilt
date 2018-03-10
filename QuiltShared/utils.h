#ifndef Q_UTILS_H
#define Q_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

	int doSHA256(const unsigned char *input, size_t ilen, unsigned char output[32]);
	int doAES(int mode, const unsigned char iv[16], const unsigned char key[32], const unsigned char *input, size_t ilen, unsigned char *output);
	int calculate_random(const unsigned char iv[16], const char* psk, long timestamp, unsigned char output[16]);

#ifdef __cplusplus
};
#endif

#endif //Q_UTILS_H
