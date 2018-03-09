#ifndef SIMP_BUF_H
#define SIMP_BUF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	unsigned char* data;
	size_t capacity;
	size_t length;
} buffer;

void buffer_init(buffer* buf);
void buffer_free(buffer* buf);

size_t buffer_available(buffer* buf);

unsigned char* buffer_raw_header(buffer* buf, size_t required_len);
size_t buffer_peek(buffer* buf, unsigned char* output, size_t olen);
size_t buffer_pop(buffer* buf, size_t len);
size_t buffer_append(buffer* buf, const unsigned char* input, size_t ilen);

#ifdef __cplusplus
};
#endif

#endif //SIMP_BUF_H
