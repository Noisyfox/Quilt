#include <assert.h>

#include "uv.h"
#include "tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "utils.h"

#define DEFAULT_BACKLOG 10

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOST "www.noisyfox.io"
#define PORT 443

#define PSK "this is a key!"

#define EQ(a,b) (((void*)(a)) == ((void*)(b)))

enum quilt_tls_state
{
	Q_TLS_INIT = 0,
	Q_TLS_CLIENT_HELLO,
	Q_TLS_APPLICATION_DATA,
	Q_TLS_FINISH
};

typedef struct
{
	BOOL is_comrade; // Товарищ, водка!
	quilt_tls_state tls_state;

	uv_tcp_t* client;
	uv_tcp_t* mock;

	buffer client_buffer;
	buffer mock_buffer;
} client_ctx;

void context_init(client_ctx* ctx)
{
	memset(ctx, 0, sizeof(client_ctx));

	ctx->tls_state = Q_TLS_INIT;
	buffer_init(&ctx->client_buffer);
	buffer_init(&ctx->mock_buffer);
}

void context_free(client_ctx* ctx)
{
	buffer_free(&ctx->client_buffer);
	buffer_free(&ctx->mock_buffer);

	free(ctx);
}


typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;


static void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	buf->base = (char*)malloc(size);
	assert(buf->base != NULL && "Memory allocation failed");
	buf->len = size;
}

void on_closed(uv_handle_t* handle)
{
	free(handle);
}

void close_client(client_ctx* ctx)
{
	if (ctx->mock && !uv_is_closing((uv_handle_t*)ctx->mock))
	{
		uv_close((uv_handle_t*)ctx->mock, on_closed);
	}
	if (ctx->client && !uv_is_closing((uv_handle_t*)ctx->client))
	{
		uv_close((uv_handle_t*)ctx->client, on_closed);
	}

	context_free(ctx);
}

void on_send(uv_write_t* req, int status) {
	write_req_t* rq = (write_req_t*)req;

	uv_stream_t* tcp = req->handle;

	free(rq->buf.base);
	free(rq);

	client_ctx* ctx = (client_ctx*)tcp->data;

	if(status)
	{
		fprintf(stderr, "Write error!");
		close_client(ctx);
	}
}

static void mark_tls_failed(client_ctx* ctx)
{
	buffer_free(&ctx->client_buffer);
	ctx->tls_state = Q_TLS_FINISH;
	ctx->is_comrade = FALSE;
}

void on_client_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		if (buf->base)
		{
			free(buf->base);
		}
		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
		rq->buf = *buf;
		rq->buf.len = nread;

		if (ctx->tls_state != Q_TLS_FINISH) {
			if (buffer_append(&ctx->client_buffer, (unsigned char*)rq->buf.base, nread) != nread)
			{
				fprintf(stderr, "Client data parse error! buffer_append failed. Enter mock mode.\n");
				mark_tls_failed(ctx);
				goto bridge;
			}
			// Parse tls
			tls_record record;
			int rs = tls_peek_next_record(&ctx->client_buffer, &record);
			if (rs == 0)
			{
				if (ctx->tls_state == Q_TLS_INIT)
				{
					tls_handshake handshake;
					if (tls_extract_handshake(&record, 0, &handshake, NULL))
					{
						fprintf(stderr, "Client data parse error! tls_extract_handshake failed. Enter mock mode.\n");
						mark_tls_failed(ctx);

						goto bridge;
					}

					// Should be client hello record
					if (handshake.msg_type != MBEDTLS_SSL_HS_CLIENT_HELLO || handshake.msg_len < 38)
					{
						fprintf(stderr, "Client data parse error! Client hello parse failed. Enter mock mode.\n");
						mark_tls_failed(ctx);

						goto bridge;
					}

					// Read random
					unsigned char* random = handshake.buf_msg + 2;
					Q_DEBUG_BUF("Client random received", random, 32);

					// Check random
					long t = mbedtls_time(NULL) / 60 / 60;
					int is_secret_random = FALSE;
					int rv = 0;
					unsigned char target_random[16];
					for (int i = -1; i <= 1; i++)
					{
						rv |= calculate_random(random, PSK, t + i, target_random) != 0;
						is_secret_random |= mbedtls_ssl_safer_memcmp(target_random, random + 16, 16) == 0;
					}
					rv = rv | (!is_secret_random);
					if (rv)
					{
						fprintf(stderr, "Client random check failed! Enter mock mode.\n");
						mark_tls_failed(ctx);

						goto bridge;
					}
					// Random check pass! For now it looks good.
					ctx->tls_state = Q_TLS_CLIENT_HELLO;
					ctx->is_comrade = true;
					fprintf(stderr, "Client random check pass!\n");
				}
				else if (ctx->tls_state == Q_TLS_CLIENT_HELLO)
				{
					// Wait until client send application data
				}

				if (tls_pop_record(&ctx->client_buffer, &record))
				{
					mark_tls_failed(ctx);

					goto bridge;
				}
			}
			else if (rs != MBEDTLS_ERR_SSL_WANT_READ)
			{
				// Error
				fprintf(stderr, "Client data parse error! tls_peek_next_record failed. Enter mock mode.\n");
				mark_tls_failed(ctx);

				goto bridge;
			}
		}
		else
		{
			// Process & proxy
			//return;
		}

bridge:
		if (uv_write(&rq->req, (uv_stream_t*)ctx->mock, &rq->buf, 1, on_send))
		{
			fprintf(stderr, "Write error!");
			close_client(ctx);
		}
	}
}

void on_mock_server_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		if (buf->base)
		{
			free(buf->base);
		}

		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
		rq->buf = *buf;
		rq->buf.len = nread;

		if(uv_write(&rq->req, (uv_stream_t*)ctx->client, &rq->buf, 1, on_send))
		{
			fprintf(stderr, "Write error!");
			close_client(ctx);
		}
	}
}

void on_mock_connect(uv_connect_t* req, int status) {
	client_ctx* ctx = (client_ctx*)req->data;

	free(req);

	if (status)
	{
		fprintf(stderr, "Mock server connection error\n");
		close_client(ctx);
		return;
	}

	fprintf(stderr, "Mock server connected!\n");
	
	// Start bridging server & client
	uv_read_start((uv_stream_t*)ctx->client, alloc_buffer, on_client_recv);
	uv_read_start((uv_stream_t*)ctx->mock, alloc_buffer, on_mock_server_recv);
}

void on_mock_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
	client_ctx* ctx = (client_ctx*)resolver->data;
	uv_loop_t* loop = resolver->loop;
	free(resolver);

	if(status < 0)
	{
		fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
		close_client(ctx);
		return;
	}

	char addr[17] = { '\0' };
	uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
	fprintf(stderr, "%s\n", addr);

	uv_connect_t *connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
	uv_tcp_t *socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, socket);
	socket->data = ctx;
	ctx->mock = socket;
	connect_req->data = ctx;

	if(uv_tcp_connect(connect_req, socket, (const struct sockaddr*) res->ai_addr, on_mock_connect))
	{
		free(connect_req);
		close_client(ctx);
	}

	uv_freeaddrinfo(res);
}

void on_new_connection(uv_stream_t *server, int status) {
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		// error!
		return;
	}

	fprintf(stderr, "New connection!\n");

	uv_tcp_t *client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, client);
	if (uv_accept(server, (uv_stream_t*)client) == 0) {
		// Connect to target
		client_ctx* ctx = (client_ctx*)malloc(sizeof(client_ctx));
		context_init(ctx);

		ctx->client = client;
		client->data = ctx;
		uv_getaddrinfo_t* resolver = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
		resolver->data = ctx;

		struct addrinfo hints;
		hints.ai_family = PF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = 0;

		if (uv_getaddrinfo(server->loop, resolver, on_mock_resolved, HOST, STR(PORT), &hints))
		{
			free(resolver);
			close_client(ctx);
		}
	}
	else
	{
		free(client);
	}
}

int main()
{
	uv_loop_t* loop = uv_default_loop();

	uv_tcp_t server;
	uv_tcp_init(loop, &server);

	struct sockaddr_in addr;
	uv_ip4_addr("127.0.0.1", PORT, &addr);

	uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

	int r = uv_listen((uv_stream_t*)&server, DEFAULT_BACKLOG, on_new_connection);
	if (r) {
		fprintf(stderr, "Listen error %s\n", uv_strerror(r));
		return 1;
	}

	return uv_run(loop, UV_RUN_DEFAULT);
}
