#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "uv_tls.h"
#include "tls.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOST "www.noisyfox.io"
#define PORT 8043

#define GET_REQUEST "GET / HTTP/1.1\r\nHost: " HOST "\r\nConnection: close\r\n\r\n"

#define PSK "this is a key!"

enum quilt_random_state {
	Q_RND_INIT = 0,
	Q_RND_TIME, // After unix time field filled
	Q_RND_FINISH
};

typedef struct
{
	uv_tls_t* client;
	uv_tcp_t* connection;
	quilt_random_state rnd_state;

	buffer buf_read;
} quilt_ctx;

static void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	buf->base = (char*)malloc(size);
	assert(buf->base != NULL && "Memory allocation failed");
	buf->len = size;
}

static void context_init(quilt_ctx* ctx)
{
	ctx->client = NULL;
	ctx->connection = NULL;
	ctx->rnd_state = Q_RND_INIT;
	
	buffer_init(&ctx->buf_read);
}

static void context_free(quilt_ctx* ctx)
{
	FREE(ctx->client);
	FREE(ctx->connection);
	buffer_free(&ctx->buf_read);
}

static int quilt_fill_random(quilt_ctx* ctx, unsigned char *output)
{
	int rv;
	// Generate iv
	if ((rv = mbedtls_ctr_drbg_random(&ctx->client->tls_eng.ctr_drbg, output, 16)))
	{
		return rv;
	}
	mbedtls_time_t t = mbedtls_time(NULL);

	rv = calculate_random(output, PSK, (long)(t / 60 / 60), output + 16);

	Q_DEBUG_BUF("Client random generated", output, 32);

	return rv;
}

static int quilt_random(uv_tls_t* h, unsigned char *output, size_t output_len)
{
	quilt_ctx* ctx = (quilt_ctx*)h->data;

	if (ctx->rnd_state == Q_RND_INIT)
	{
		if (output_len != 4 && output_len != 28)
		{
			return -1;
		}

		int rv;
		if (output_len == 4)
		{
			// Unix time field
			rv = quilt_fill_random(ctx, output);
			ctx->rnd_state = Q_RND_TIME;
		}
		else
		{
			// Directly goes into random field, need to overwrite unix time field
			output -= 4;
			rv = quilt_fill_random(ctx, output);
			ctx->rnd_state = Q_RND_FINISH;
		}

		if(rv)
		{
			return rv;
		}
	}
	else if (ctx->rnd_state == Q_RND_TIME)
	{
		if (output_len != 28)
		{
			return -1;
		}
		// Simply mark as finish since all random field has generated in previous state
		ctx->rnd_state = Q_RND_FINISH;
	}
	else
	{
		return -1;
	}

	if(ctx->rnd_state == Q_RND_FINISH)
	{
		h->random_cb = NULL;
	}

	return 0;
}



typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

void on_close(uv_handle_t* peer) {
	quilt_ctx* ctx = (quilt_ctx*)peer->data;
	if (ctx) {
		context_free(ctx);
		free(ctx);
	}
	else
	{
		free(peer);
	}
	fprintf(stderr, "Closed ok!\n");
}

void on_tls_close(uv_tls_t* h) {
	quilt_ctx* ctx = (quilt_ctx*)h->data;
	context_free(ctx);
	free(ctx);
	fprintf(stderr, "TLS closed ok!\n");
}

void receive_response(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	quilt_ctx* ctx = (quilt_ctx*)stream->data;

//	fprintf(stderr, "receive_response!");
	if (nread < 0) {
		/* Error or EOF */
		uv_close((uv_handle_t*)ctx->connection, on_close);
	}
	else {
		// Append to in buffer
		if (buffer_append(&ctx->buf_read, (unsigned char*)buf->base, nread) != nread)
		{
			fprintf(stderr, "Server data parse error! buffer_append failed.\n");
			uv_close((uv_handle_t*)ctx->connection, on_close);
			return;
		}

		// Parse tls
		tls_record record;
		int rs;
		while (true) {
			// Peek next record from buffer
			if ((rs = tls_peek_next_record(&ctx->buf_read, &record)))
			{
				if (rs != MBEDTLS_ERR_SSL_WANT_READ)
				{
					fprintf(stderr, "tls_peek_next_record failed.\n");
				}
				break;
			}

			// Handle next record
			if(record.msg_type != MBEDTLS_SSL_MSG_APPLICATION_DATA)
			{
				fprintf(stderr, "Should be application data!\n");
				rs = MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
				break;
			}
			fwrite(record.buf_msg, sizeof(char), record.msg_len, stdout);

			// Remove record from buffer
			if ((rs = tls_pop_record(&ctx->buf_read, &record)))
			{
				fprintf(stderr, "tls_pop_record failed.\n");
				break;
			}
		}
		if (rs != MBEDTLS_ERR_SSL_WANT_READ)
		{
			fprintf(stderr, "Server data parse error!\n");
			uv_close((uv_handle_t*)ctx->connection, on_close);
			return;
		}
	}
}

void on_send(uv_write_t* req, int status) {
	write_req_t* rq = (write_req_t*)req;

	uv_stream_t* tcp = req->handle;
	quilt_ctx* ctx = (quilt_ctx*)tcp->data;

	free(rq->buf.base);
	free(rq);

	if (status == 0) {
		fprintf(stderr, "Write ok!\n");
//		uv_read_start(tcp, alloc_buffer, receive_response);
	}
	else {
		fprintf(stderr, "Write error!");
		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));

		uv_close((uv_handle_t*)ctx->connection, on_close);
	}
}

void on_handshake(uv_tls_t* h, int status)
{
	if(status)
	{
		fprintf(stderr, "TLS handshake error!\n");
		uv_tls_close(h, on_tls_close);
		return;
	}

	fprintf(stderr, "TLS handshake success!\n");

	// Shutdown ssl session and take over the connection
	quilt_ctx* ctx = (quilt_ctx*)h->data;
	uv_tls_shutdown(h);
	free(h);
	ctx->client = NULL;
	ctx->connection->data = ctx;

	if(uv_read_start((uv_stream_t*)ctx->connection, alloc_buffer, receive_response))
	{
		uv_close((uv_handle_t*)ctx->connection, on_close);
		return;
	}

//	uv_tls_read(h, receive_response);
//
////	uv_tls_close(h, on_tls_close);
//
//	write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
//	char* request_data = _strdup(GET_REQUEST);
//	rq->buf = uv_buf_init(request_data, strlen(request_data));
//	uv_tls_write(&rq->req, h, &rq->buf, on_send);
}

void on_connect(uv_connect_t* req, int status) {
	uv_stream_t* tcp = req->handle;

	free(req);

	if (status)
	{
		fprintf(stderr, "TCP connection error\n");
		uv_close((uv_handle_t*)tcp, on_close);
		return;
	}

	fprintf(stderr, "Connected!");

	uv_tls_t *client = (uv_tls_t*)malloc(sizeof *client);
	if (uv_tls_init((uv_tcp_t*)tcp, client)) {
		free(client);
		fprintf(stderr, "TLS setup error\n");

		uv_close((uv_handle_t*)tcp, on_close);
		return;
	}

	quilt_ctx* ctx = (quilt_ctx*)malloc(sizeof quilt_ctx);
	if(!ctx)
	{
		uv_tls_close(client, on_tls_close);
		return;
	}

	context_init(ctx);
	ctx->client = client;
	ctx->connection = (uv_tcp_t*)tcp;

	// Inject out own random function
	client->data = ctx;
	client->random_cb = quilt_random;

	if(uv_tls_handshake(client, HOST, on_handshake))
	{
		uv_tls_close(client, on_tls_close);
	}
}

void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
	if (status < 0) {
		fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
		return;
	}

	char addr[17] = { '\0' };
	uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
	fprintf(stderr, "%s\n", addr);

	uv_connect_t *connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
	uv_tcp_t *socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(resolver->loop, socket);

	uv_tcp_connect(connect_req, socket, (const struct sockaddr*) res->ai_addr, on_connect);

	uv_freeaddrinfo(res);
}

int main() {
	uv_loop_t* loop = uv_default_loop();
	
	struct addrinfo hints;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	uv_getaddrinfo_t resolver;
	fprintf(stderr, HOST " is... ");
	int r = uv_getaddrinfo(loop, &resolver, on_resolved, "127.0.0.1", STR(PORT), &hints);

	if (r) {
		fprintf(stderr, "getaddrinfo call error %s\n", uv_err_name(r));
		return 1;
	}

	return uv_run(loop, UV_RUN_DEFAULT);
}
