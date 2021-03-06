#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "uv.h"
#include "tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "utils.h"
#include "config.h"

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
	config_t* config;

	int tls_major_ver;
	int tls_minor_ver;

	int is_comrade; // Товарищ, водка!
	int tls_state;

	uv_tcp_t* client;
	uv_tcp_t* mock;
	uv_tcp_t* server;

	buffer client_buffer;
	buffer server_buffer;
} client_ctx;

static void context_init(client_ctx* ctx)
{
	memset(ctx, 0, sizeof(client_ctx));

	ctx->tls_state = Q_TLS_INIT;
	buffer_init(&ctx->client_buffer);
	buffer_init(&ctx->server_buffer);
}

static void context_free(client_ctx* ctx)
{
	free(ctx->server);
	free(ctx->mock);
	free(ctx->client);
	buffer_free(&ctx->client_buffer);
	buffer_free(&ctx->server_buffer);
}


static void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	buf->base = (char*)malloc(size);
	assert(buf->base != NULL && "Memory allocation failed");
	buf->len = size;
}

static void on_close(uv_ext_close_t* req)
{
	client_ctx* ctx = (client_ctx*)req->data;
	free(req->handles);
	free(req);

	context_free(ctx);
	free(ctx);
	Q_DEBUG_MSG("Connection closed!");
}

static void close_client(client_ctx* ctx)
{
	uv_ext_close_t* close_req = (uv_ext_close_t*)malloc(sizeof(uv_ext_close_t));
	close_req->data = ctx;
	close_req->handles = (uv_handle_t**)malloc(sizeof(uv_handle_t*) * 3);
	size_t i = 0;

	if (ctx->mock)
	{
		close_req->handles[i++] = (uv_handle_t*)ctx->mock;
	}
	if (ctx->client)
	{
		close_req->handles[i++] = (uv_handle_t*)ctx->client;
	}
	if (ctx->server)
	{
		close_req->handles[i++] = (uv_handle_t*)ctx->server;
	}
	close_req->handle_count = i;

	uv_ext_close(close_req, on_close);
}

static void on_send(uv_write_t* req, int status) {
	uv_stream_t* tcp = req->handle;
	client_ctx* ctx = (client_ctx*)tcp->data;

	uv_ext_write_cleanup(req);

	if(status)
	{
		fprintf(stderr, "Write error!");
		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));
		close_client(ctx);
	}
}

static void mark_tls_failed(client_ctx* ctx)
{
	buffer_free(&ctx->client_buffer);
	buffer_free(&ctx->server_buffer);
	FLAG_SET(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH);
	ctx->is_comrade = 0;
}

static int client_handle_next_record(client_ctx* ctx, tls_record* record)
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
		int is_secret_random = 0;
		int rv = 0;
		unsigned char target_random[16];
		for (int i = -1; i <= 1; i++)
		{
			rv |= calculate_random(random, ctx->config->password, t + i, target_random) != 0;
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
		ctx->is_comrade = 1;
		Q_DEBUG_MSG("Client random check pass!");
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

static void on_client_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		free(buf->base);
		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		if (!FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH)) {
			if (buffer_append(&ctx->client_buffer, (unsigned char*)buf->base, nread) != nread)
			{
				fprintf(stderr, "Client data parse error! buffer_append failed. Enter mock mode.\n");
				mark_tls_failed(ctx);
				goto bridge;
			}
			// Parse tls
			tls_record record;
			int rs;
			while (1) {
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
				free(buf->base);
				close_client(ctx);
				return;
			}
		}
		else
		{
			// Process & proxy
			if(ctx->is_comrade)
			{
				Q_DEBUG_BUF("Client data", (unsigned char*)buf->base, nread);

				// Append to in buffer
				if (buffer_append(&ctx->client_buffer, (unsigned char*)buf->base, nread) != nread)
				{
					free(buf->base);
					fprintf(stderr, "Client data parse error! buffer_append failed.\n");
					close_client(ctx);
					return;
				}
				free(buf->base);

				// Parse tls
				tls_record record;
				int rs;
				while (1) {
					// Peek next record from buffer
					if ((rs = tls_peek_next_record(&ctx->client_buffer, &record)))
					{
						if (rs != MBEDTLS_ERR_SSL_WANT_READ)
						{
							fprintf(stderr, "tls_peek_next_record failed.\n");
						}
						break;
					}

					// Handle next record
					if (record.msg_type != MBEDTLS_SSL_MSG_APPLICATION_DATA)
					{
						fprintf(stderr, "Should be application data!\n");
						rs = MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
						break;
					}

					if (ctx->tls_major_ver != record.major_ver || ctx->tls_minor_ver != record.minor_ver)
					{
						fprintf(stderr, "TLS version mismatch!\n");
						rs = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
						break;
					}

					Q_DEBUG_BUF("Client message", record.buf_msg, record.msg_len);
					if ((rs = uv_ext_write((uv_stream_t*)ctx->server, record.buf_msg, record.msg_len, NULL, on_send)))
					{
						fprintf(stderr, "uv_ext_write failed.\n");
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
					fprintf(stderr, "Client data parse error!\n");
					close_client(ctx);
					return;
				}
				return;
			}
		}

	bridge:
		if(uv_ext_write2((uv_stream_t*)ctx->mock, (unsigned char*)buf->base, nread, NULL, 1, on_send))
		{
			free(buf->base);
			fprintf(stderr, "Write error!");
			close_client(ctx);
		}
	}
}

static void on_server_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		free(buf->base);
		close_client(ctx);

		return;
	}
	else
	{
		Q_DEBUG_BUF("Server response", (const unsigned char*)buf->base, nread);
		if (buffer_append(&ctx->server_buffer, (const unsigned char*)buf->base, nread) != nread)
		{
			free(buf->base);
			fprintf(stderr, "Server data enclose error! buffer_append failed.\n");
			close_client(ctx);
			return;
		}
		free(buf->base);

		// TODO: Pause send timer
		// Check if write buffer has enough content to send as a batch
		if (uv_write_tls_application_data_all((uv_stream_t*)ctx->client, ctx->tls_major_ver, ctx->tls_minor_ver, &ctx->server_buffer, on_send))
		{
			fprintf(stderr, "Client data enclose error! uv_write_tls_application_data_full failed.\n");
			close_client(ctx);
			return;
		}

		// TODO: If has data remaining, start timer
	}
}

static void on_server_connect(uv_connect_t* req, int status) {
	client_ctx* ctx = (client_ctx*)req->data;

	free(req);

	if (status)
	{
		fprintf(stderr, "Target server connection error %s\n", uv_strerror(status));
		close_client(ctx);
		return;
	}

	Q_DEBUG_MSG("Target server connected!");

	// Start bridging server & client
	uv_read_start((uv_stream_t*)ctx->client, alloc_buffer, on_client_recv);
	uv_read_start((uv_stream_t*)ctx->server, alloc_buffer, on_server_recv);
}

static int mock_handle_next_record(client_ctx* ctx, tls_record* record)
{
	if (FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH))
	{
		fprintf(stderr, "Handshaked already finished!\n");
		return MBEDTLS_ERR_SSL_UNEXPECTED_RECORD;
	}

	int rv;
	if (!FLAG_TEST(ctx->tls_state, Q_TLS_SERVER_HELLO))
	{
		if (!FLAG_TEST(ctx->tls_state, Q_TLS_CLIENT_HELLO))
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

			// Save ssl version
			ctx->tls_major_ver = record->major_ver;
			ctx->tls_minor_ver = record->minor_ver;

			// All handshake should finished!
			FLAG_SET(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH);
			Q_DEBUG_MSG("Handshake finished!");
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

static void on_mock_server_recv(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	client_ctx* ctx = (client_ctx*)stream->data;

	if (nread < 0)
	{
		free(buf->base);
		close_client(ctx);

		return;
	}
	if (nread > 0)
	{
		if (!FLAG_TEST(ctx->tls_state, Q_TLS_HANDSHAKE_FINISH)) {
			if (buffer_append(&ctx->server_buffer, (unsigned char*)buf->base, nread) != nread)
			{
				fprintf(stderr, "Mock data parse error! buffer_append failed. Enter mock mode.\n");
				mark_tls_failed(ctx);
				goto bridge;
			}
			// Parse tls
			tls_record record;
			int rs;
			while (1) {
				// Peek next record from buffer
				if ((rs = tls_peek_next_record(&ctx->server_buffer, &record)))
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
				if ((rs = tls_pop_record(&ctx->server_buffer, &record)))
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
				if(buffer_available(&ctx->client_buffer) || buffer_available(&ctx->server_buffer))
				{
					fprintf(stderr, "Handshake finished with remain data in buffer. Not expected behavior. Enter mock mode.\n");
					mark_tls_failed(ctx);

					goto bridge;
				}
				if(!ctx->is_comrade)
				{
					goto bridge;
				}

				// Close mock server connection. Ignore the callback here
				// Since it will be freed anyway by close_client().
				uv_close((uv_handle_t*)ctx->mock, NULL);

				// Stop reading from client socket, wait until we connect to our target server
				if(uv_read_stop((uv_stream_t*)ctx->client))
				{
					goto err;
				}
				// Start connect to server
				uv_connect_t *connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
				uv_tcp_t *socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
				uv_tcp_init(ctx->client->loop, socket);
				socket->data = ctx;
				ctx->server = socket;
				connect_req->data = ctx;

				if (uv_ext_resolve_connect(connect_req, socket, ctx->config->server_host, ctx->config->server_port, on_server_connect))
				{
					free(connect_req);
					close_client(ctx);
					goto err;
				}
			}
		}
		else
		{
			if(ctx->is_comrade)
			{
				// Should not reach here!
				fprintf(stderr, "Received data from mock server after switch to proxy mode! Something went wrong!");
				goto err;
			}
		}

	bridge:
		if (uv_ext_write2((uv_stream_t*)ctx->client, (unsigned char*)buf->base, nread, NULL, 1, on_send))
		{
			free(buf->base);
			fprintf(stderr, "Write error!");
			close_client(ctx);
		}
		return;
	err:
		free(buf->base);
		close_client(ctx);
	}
}

static void on_mock_connect(uv_connect_t* req, int status) {
	client_ctx* ctx = (client_ctx*)req->data;

	free(req);

	if (status)
	{
		fprintf(stderr, "Mock server connection error %s\n", uv_strerror(status));
		close_client(ctx);
		return;
	}

	Q_DEBUG_MSG("Mock server connected!");

	// Start bridging mock server & client
	uv_read_start((uv_stream_t*)ctx->client, alloc_buffer, on_client_recv);
	uv_read_start((uv_stream_t*)ctx->mock, alloc_buffer, on_mock_server_recv);
}

static void on_new_connection(uv_stream_t *server, int status) {
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		// error!
		return;
	}

	config_t* config = (config_t*)server->data;

	Q_DEBUG_MSG("New connection!");

	uv_tcp_t *client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, client);
	if (uv_accept(server, (uv_stream_t*)client) == 0) {
		// Init context
		client_ctx* ctx = (client_ctx*)malloc(sizeof(client_ctx));
		context_init(ctx);
		ctx->config = config;
		ctx->client = client;
		client->data = ctx;

		// Connect to mock server
		uv_connect_t *connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
		uv_tcp_t *socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(server->loop, socket);
		socket->data = ctx;
		ctx->mock = socket;
		connect_req->data = ctx;

		const char* target = config->mocking_ip;
		if (!target)
		{
			target = config->mocking_host;
		}
		if(uv_ext_resolve_connect(connect_req, socket, target, config->mocking_port, on_mock_connect))
		{
			free(connect_req);
			close_client(ctx);
		}
	}
	else
	{
		free(client);
	}
}

static void on_signal(uv_signal_t *handle, int signum) {
	uv_stop(handle->loop);
}

int main(int argc, char** argv)
{
	progname = argv[0];

	config_t config;
	int r = parse_config(argc, argv, &config);
	switch (r)
	{
	case CFG_NORMAL_EXIT:
		return 0;
	case CFG_NORMAL:
		break;
	default:
		return -1;
	}

	uv_loop_t* loop = uv_default_loop();

	uv_signal_t sigterm;
	uv_signal_t sigint;
	uv_signal_init(loop, &sigterm);
	uv_unref((uv_handle_t*)&sigterm);
	uv_signal_init(loop, &sigint);
	uv_unref((uv_handle_t*)&sigint);
	uv_signal_start(&sigterm, on_signal, SIGTERM);
	uv_signal_start(&sigint, on_signal, SIGINT);

	uv_tcp_t server;
	uv_tcp_init(loop, &server);
	server.data = &config;

	struct sockaddr_in addr;
	uv_ip4_addr("127.0.0.1", config.local_port, &addr);

	uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

	r = uv_listen((uv_stream_t*)&server, DEFAULT_BACKLOG, on_new_connection);
	if (r) {
		fprintf(stderr, "Listen error %s\n", uv_strerror(r));
		return 1;
	}

	fprintf(stderr, "Listen on 127.0.0.1:%d\n",  config.local_port);

	int rv = uv_run(loop, UV_RUN_DEFAULT);

	uv_signal_stop(&sigterm);
	uv_signal_stop(&sigint);

	return rv;
}
