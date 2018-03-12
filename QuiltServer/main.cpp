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
#define HOST_IP "172.104.122.122"
#define PORT 443

#define PSK "this is a key!"

#define EQ(a,b) (((void*)(a)) == ((void*)(b)))
#define FLAG_TEST(v, f) (((v) & (f)) == (f))
#define FLAG_SET(v, f) ((v) = ((v) | (f)))

enum quilt_tls_state
{
	Q_TLS_INIT = 1,
	Q_TLS_CLIENT_HELLO = 1 << 1,
	Q_TLS_SERVER_HELLO = 1 << 2,
	Q_TLS_SERVER_HELLO_DONE = 1 << 3,
	Q_TLS_CLIENT_CCS = 1 << 4, // CCS = ChangeCipherSpec
	Q_TLS_SERVER_CCS = 1 << 5,
	Q_TLS_CLIENT_HANDSHAKE_FIN = 1 << 6,
	Q_TLS_SERVER_HANDSHAKE_FIN = 1 << 7,
	Q_TLS_HANDSHAKE_FINISH = 1 << 8
};

typedef struct
{
	BOOL is_comrade; // Товарищ, водка!
	int tls_state;

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
	fprintf(stderr, "Connection closed!");
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
	buffer_free(&ctx->mock_buffer);
	FLAG_SET(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH);
	ctx->is_comrade = FALSE;
}

int client_handle_next_record(client_ctx* ctx, tls_record* record)
{
	if(FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH))
	{
		fprintf(stderr, "Handshaked already finished!\n");
		return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
	}

	int rv;
	if (!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_HELLO))
	{
		tls_handshake handshake;
		if ((rv = tls_extract_handshake(record, 0, &handshake, NULL)))
		{
			fprintf(stderr, "tls_extract_handshake failed.\n");
			return rv;
		}

		// Should be client hello record
		if (handshake.msg_type != MBEDTLS_SSL_HS_CLIENT_HELLO || handshake.msg_len < 38)
		{
			fprintf(stderr, "Client hello parse failed.\n");
			return MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
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
			fprintf(stderr, "Client random check failed!\n");
			return MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
		}
		// Random check pass! For now it looks good.
		// TODO: check random replay attack
		FLAG_SET(ctx->tls_state, Q_TLS_CLIENT_HELLO);
		ctx->is_comrade = true;
		fprintf(stderr, "Client random check pass!\n");
	}
	else
	{
		if (record->msg_type == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC)
		{
			// Check current state
			if (!FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_HELLO_DONE))
			{
				fprintf(stderr, "Client CCS received before server hello done.\n");
				return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
			}

			if(FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_CCS))
			{
				// Dup?
				fprintf(stderr, "Duplicated Change Cipher Spec received.\n");
				return MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC;
			}
			// TODO: verify record
			FLAG_SET(ctx->tls_state, Q_TLS_CLIENT_CCS);
		}
		else if (record->msg_type == MBEDTLS_SSL_MSG_HANDSHAKE)
		{
			if(!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_CCS))
			{
				// Extract messages
				tls_handshake handshake;
				size_t offset = 0;
				while (offset < record->msg_len)
				{
					if ((rv = tls_extract_handshake(record, 0, &handshake, &offset)))
					{
						fprintf(stderr, "tls_extract_handshake failed.\n");
						return rv;
					}
				}

				return 0; // Ignore all handshake record before we received CCS
			}

			if (FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_HANDSHAKE_FIN))
			{
				// Dup?
				fprintf(stderr, "Duplicated handshake finish received.\n");
				return MBEDTLS_ERR_SSL_BAD_HS_FINISHED;
			}
			FLAG_SET(ctx->tls_state, Q_TLS_CLIENT_HANDSHAKE_FIN);
		}
		else if (record->msg_type == MBEDTLS_SSL_MSG_APPLICATION_DATA)
		{
			fprintf(stderr, "Shouldn't see Application Data during handshaking!\n");
			return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
		}
	}

	return 0;
}

int mock_handle_next_record(client_ctx* ctx, tls_record* record)
{
	if (FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH))
	{
		fprintf(stderr, "Handshaked already finished!\n");
		return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
	}

	int rv;
	if(!FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_HELLO))
	{
		if(!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_HELLO))
		{
			// Client hello must happen first!
			fprintf(stderr, "Server data received before Client Hello.\n");
			return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
		}

		tls_handshake handshake;
		if ((rv = tls_extract_handshake(record, 0, &handshake, NULL)))
		{
			fprintf(stderr, "tls_extract_handshake failed.\n");
			return rv;
		}

		// Should be server hello record
		if (handshake.msg_type != MBEDTLS_SSL_HS_SERVER_HELLO || handshake.msg_len < 38)
		{
			fprintf(stderr, "Server hello parse failed.\n");
			return MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
		}

		FLAG_SET(ctx->tls_state, Q_TLS_SERVER_HELLO);
	}
	else
	{
		if (record->msg_type == MBEDTLS_SSL_MSG_HANDSHAKE)
		{
			if (!FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_CCS))
			{
				// Extract messages
				tls_handshake handshake;
				size_t offset = 0;
				while (offset < record->msg_len)
				{
					if ((rv = tls_extract_handshake(record, 0, &handshake, &offset)))
					{
						fprintf(stderr, "tls_extract_handshake failed.\n");
						return rv;
					}

					if (handshake.msg_type == MBEDTLS_SSL_HS_SERVER_HELLO_DONE)
					{
						if (handshake.msg_len != 0)
						{
							fprintf(stderr, "Malformed Server Hello Done.\n");
							return MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE;
						}

						if (FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_HELLO_DONE))
						{
							// Dup?
							fprintf(stderr, "Duplicated Server Hello Done received.\n");
							return MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE;
						}
						FLAG_SET(ctx->tls_state, Q_TLS_SERVER_HELLO_DONE);
					}
				}

				return 0; // Ignore all handshake record before we received CCS
			}

			if (FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_HANDSHAKE_FIN))
			{
				// Dup?
				fprintf(stderr, "Duplicated handshake finish received.\n");
				return MBEDTLS_ERR_SSL_BAD_HS_FINISHED;
			}
			if (!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_HANDSHAKE_FIN))
			{
				fprintf(stderr, "Server handshake finish received before Client Handshake Finished.\n");
				return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
			}
			FLAG_SET(ctx->tls_state, Q_TLS_SERVER_HANDSHAKE_FIN);

			// All handshake should finished!
			FLAG_SET(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH);
			fprintf(stderr, "Handshake finished!\n");
		}
		else if (record->msg_type == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC)
		{
			// Check current state
			if (!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_CCS))
			{
				fprintf(stderr, "Server CCS received before Client CCS.\n");
				return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
			}

			if (FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_CCS))
			{
				// Dup?
				fprintf(stderr, "Duplicated Change Cipher Spec received.\n");
				return MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC;
			}
			// TODO: verify record
			FLAG_SET(ctx->tls_state, Q_TLS_SERVER_CCS);
		}
		else if (record->msg_type == MBEDTLS_SSL_MSG_APPLICATION_DATA)
		{
			fprintf(stderr, "Shouldn't see Application Data during handshaking!\n");
			return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
		}
	}

	return 0;
}

void on_client_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		FREE(buf->base);
		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
		rq->buf = *buf;
		rq->buf.len = nread;

		if (!FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH)) {
			if (buffer_append(&ctx->client_buffer, (unsigned char*)rq->buf.base, nread) != nread)
			{
				fprintf(stderr, "Client data parse error! buffer_append failed. Enter mock mode.\n");
				mark_tls_failed(ctx);
				goto bridge;
			}
			// Parse tls
			tls_record record;
			int rs;
			while (true) {
				// Peek next record from buffer
				if((rs = tls_peek_next_record(&ctx->client_buffer, &record)))
				{
					if(rs != MBEDTLS_ERR_SSL_WANT_READ)
					{
						fprintf(stderr, "tls_peek_next_record failed.\n");
					}
					break;
				}

				// Handle next record
				if ((rs = client_handle_next_record(ctx, &record)))
				{
					break;
				}

				// Remove record from buffer
				if ((rs = tls_pop_record(&ctx->client_buffer, &record)))
				{
					fprintf(stderr, "tls_pop_record failed.\n");
					break;
				}
			}
			if (rs != MBEDTLS_ERR_SSL_WANT_READ)
			{
				fprintf(stderr, "Client data parse error! Enter mock mode.\n");
				mark_tls_failed(ctx);

				goto bridge;
			}

			if(FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH))
			{
				fprintf(stderr, "Handshake shouldn't finish from client side!\n");
				FREE(buf->base);
				close_client(ctx);
				return;
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
			FREE(buf->base);
			fprintf(stderr, "Write error!");
			close_client(ctx);
		}
	}
}

void on_mock_server_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		FREE(buf->base);
		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
		rq->buf = *buf;
		rq->buf.len = nread;

		if (!FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH)) {
			if (buffer_append(&ctx->mock_buffer, (unsigned char*)rq->buf.base, nread) != nread)
			{
				fprintf(stderr, "Mock data parse error! buffer_append failed. Enter mock mode.\n");
				mark_tls_failed(ctx);
				goto bridge;
			}
			// Parse tls
			tls_record record;
			int rs;
			while (true) {
				// Peek next record from buffer
				if ((rs = tls_peek_next_record(&ctx->mock_buffer, &record)))
				{
					if (rs != MBEDTLS_ERR_SSL_WANT_READ)
					{
						fprintf(stderr, "tls_peek_next_record failed.\n");
					}
					break;
				}

				// Handle next record
				if ((rs = mock_handle_next_record(ctx, &record)))
				{
					break;
				}

				// Remove record from buffer
				if ((rs = tls_pop_record(&ctx->mock_buffer, &record)))
				{
					fprintf(stderr, "tls_pop_record failed.\n");
					break;
				}
			}
			if (rs != MBEDTLS_ERR_SSL_WANT_READ)
			{
				fprintf(stderr, "Mock data parse error! Enter mock mode.\n");
				mark_tls_failed(ctx);

				goto bridge;
			}

			if (FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH))
			{
				// Make sure all data in tls buffers are consumed
				if(buffer_available(&ctx->client_buffer) || buffer_available(&ctx->mock_buffer))
				{
					fprintf(stderr, "Handshake finished with remain data in buffer. Not expected behavior. Enter mock mode.\n");
					mark_tls_failed(ctx);

					goto bridge;
				}

				// clean up tls buffers
				buffer_free(&ctx->client_buffer);
				buffer_free(&ctx->mock_buffer);
			}
		}
		else
		{
			// Process & proxy
			//return;
		}

	bridge:
		if(uv_write(&rq->req, (uv_stream_t*)ctx->client, &rq->buf, 1, on_send))
		{
			FREE(buf->base);
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

		if (uv_getaddrinfo(server->loop, resolver, on_mock_resolved, HOST_IP, STR(PORT), &hints))
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
	uv_ip4_addr("127.0.0.1", 8043, &addr);

	uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

	int r = uv_listen((uv_stream_t*)&server, DEFAULT_BACKLOG, on_new_connection);
	if (r) {
		fprintf(stderr, "Listen error %s\n", uv_strerror(r));
		return 1;
	}

	return uv_run(loop, UV_RUN_DEFAULT);
}
