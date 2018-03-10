#include <string.h>
#include <stdlib.h>
#include "simple_buffer.h"


void buffer_init(buffer* buf)
{
	memset(buf, 0, sizeof(buffer));
}

void buffer_free(buffer* buf)
{
	if(buf->data)
	{
		free(buf->data);
	}

	memset(buf, 0, sizeof(buffer));
}

size_t buffer_available(buffer* buf)
{
	return buf->length;
}

unsigned char* buffer_raw_header(buffer* buf, size_t required_len)
{
	if(required_len > buffer_available(buf))
	{
		return NULL;
	}

	return buf->data;
}

size_t buffer_peek(buffer* buf, unsigned char* output, size_t olen)
{
	size_t available = buffer_available(buf);
	size_t d = olen > available ? available : olen;

	if(d > 0)
	{
		memcpy(output, buf->data, d);
	}

	return d;
}

size_t buffer_pop(buffer* buf, size_t len)
{
	size_t available = buffer_available(buf);
	size_t d = len > available ? available : len;

	if(d > 0)
	{
		memmove(buf->data, buf->data + d, available - d);
		buf->length -= d;
	}

	return d;
}

size_t buffer_append(buffer* buf, const unsigned char* input, size_t ilen)
{
	if(ilen == 0 )
	{
		return 0;
	}

	size_t available = buffer_available(buf);
	size_t cap = buf->capacity;
	size_t remain = cap - available;

	if(remain < ilen)
	{
		size_t shortage = ilen - remain;
		shortage *= 2;
		if(shortage < 512)
		{
			shortage = 512;
		}
		size_t new_cap = cap + shortage;
		unsigned char* new_data = (unsigned char*)malloc(new_cap);
		if(!new_data)
		{
			return 0;
		}

		if(buf->data)
		{
			memcpy(new_data, buf->data, available);
			free(buf->data);
		}
		buf->data = new_data;
		buf->capacity = new_cap;
	}

	memcpy(buf->data + available, input, ilen);
	buf->length += ilen;

	return ilen;
}
