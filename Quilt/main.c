#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "uv_tls.h"
#include "tls.h"
#include "config.h"

typedef enum {
	Q_RND_INIT = 0,
	Q_RND_TIME, // After unix time field filled
	Q_RND_FINISH
} quilt_random_state;

typedef struct
{
	config_t* config;

	int tls_major_ver;
	int tls_minor_ver;

	uv_tcp_t* client_connection;

	uv_tls_t* server_connection_tls;
	uv_tcp_t* server_connection;

	quilt_random_state rnd_state;

	buffer buf_read;
	buffer buf_write;
} quilt_ctx;

static void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	buf->base = (char*)malloc(size);
	assert(buf->base != NULL && "Memory allocation failed");
	buf->len = size;
}

static void context_init(quilt_ctx* ctx)
{
	memset(ctx, 0, sizeof(quilt_ctx));
	ctx->rnd_state = Q_RND_INIT;
	
	buffer_init(&ctx->buf_read);
	buffer_init(&ctx->buf_write);
}

static void context_free(quilt_ctx* ctx)
{
	free(ctx->client_connection);
	free(ctx->server_connection);
	buffer_free(&ctx->buf_read);
	buffer_free(&ctx->buf_write);
}

static void on_close(uv_ext_close_t* req) {
	quilt_ctx* ctx = (quilt_ctx*)req->data;
	free(req->handles);
	free(req);

	context_free(ctx);
	free(ctx);
	Q_DEBUG_MSG("Closed ok!");
}

static void context_close(quilt_ctx* ctx)
{
	uv_ext_close_t* close_req = (uv_ext_close_t*)malloc(sizeof(uv_ext_close_t));
	close_req->data = ctx;
	close_req->handles = (uv_handle_t**)malloc(sizeof(uv_handle_t*) * 2);
	
	close_req->handles[0] = (uv_handle_t*)ctx->client_connection;
	close_req->handles[1] = (uv_handle_t*)ctx->server_connection;
	close_req->handle_count = close_req->handles[1] == NULL ? 1 : 2;

	uv_ext_close(close_req, on_close);
}

static int quilt_fill_random(quilt_ctx* ctx, unsigned char *output)
{
	int rv;
	// Generate iv
	if ((rv = mbedtls_ctr_drbg_random(&ctx->server_connection_tls->tls_eng.ctr_drbg, output, 16)))
	{
		return rv;
	}
	mbedtls_time_t t = mbedtls_time(NULL);

	rv = calculate_random(output, ctx->config->password, (long)(t / 60 / 60), output + 16);

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

static void on_send(uv_write_t* req, int status) {
	uv_stream_t* tcp = req->handle;
	quilt_ctx* ctx = (quilt_ctx*)tcp->data;

	uv_ext_write_cleanup(req);

	if (status == 0) {
		Q_DEBUG_MSG("Write ok!");
		//		uv_read_start(tcp, alloc_buffer, receive_response);
	}
	else {
		fprintf(stderr, "Write error!");
		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));

		context_close(ctx);
	}
}

static void receive_server(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	quilt_ctx* ctx = (quilt_ctx*)stream->data;

//	fprintf(stderr, "receive_response!");
	if (nread < 0) {
		/* Error or EOF */
		context_close(ctx);
		free(buf->base);
	}
	else {
		Q_DEBUG_BUF("Server response data", (unsigned char*)buf->base, nread);

		// Append to in buffer
		if (buffer_append(&ctx->buf_read, (unsigned char*)buf->base, nread) != nread)
		{
			free(buf->base);
			fprintf(stderr, "Server data parse error! buffer_append failed.\n");
			context_close(ctx);
			return;
		}
		free(buf->base);

		// Parse tls
		tls_record record;
		int rs;
		while (1) {
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

			if (ctx->tls_major_ver != record.major_ver || ctx->tls_minor_ver != record.minor_ver)
			{
				fprintf(stderr, "TLS version mismatch!\n");
				rs = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
				break;
			}

			Q_DEBUG_BUF("Server response message", record.buf_msg, record.msg_len);
			if((rs = uv_ext_write((uv_stream_t*)ctx->client_connection, record.buf_msg, record.msg_len, NULL, on_send)))
			{
				fprintf(stderr, "uv_ext_write failed.\n");
				break;
			}

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
			context_close(ctx);
			return;
		}
	}
}

static void receive_client(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	quilt_ctx* ctx = (quilt_ctx*)stream->data;

	//	fprintf(stderr, "receive_response!");
	if (nread < 0) {
		/* Error or EOF */
		free(buf->base);
		context_close(ctx);
	}
	else
	{
		Q_DEBUG_BUF("Client input", (const unsigned char*)buf->base, nread);
		if(buffer_append(&ctx->buf_write, (const unsigned char*)buf->base, nread) != nread)
		{
			free(buf->base);
			fprintf(stderr, "Client data enclose error! buffer_append failed.\n");
			context_close(ctx);
			return;
		}
		free(buf->base);

		// TODO: Pause send timer
		// Check if write buffer has enough content to send as a batch
		if(uv_write_tls_application_data_all((uv_stream_t*)ctx->server_connection, ctx->tls_major_ver, ctx->tls_minor_ver, &ctx->buf_write, on_send))
		{
			fprintf(stderr, "Client data enclose error! uv_write_tls_application_data_full failed.\n");
			context_close(ctx);
			return;
		}
		
		// TODO: If has data remaining, start timer
	}
}

static void tls_shutdown(quilt_ctx* ctx)
{
	uv_tls_t* h = ctx->server_connection_tls;
	uv_tls_shutdown(h);
	free(h);
	ctx->server_connection_tls = NULL;
	ctx->server_connection->data = ctx;
	
	Q_DEBUG_MSG("TLS shutdown ok!");
}

static void on_handshake(uv_tls_t* h, int status)
{
	quilt_ctx* ctx = (quilt_ctx*)h->data;

	// Before shutdown ssl, save ssl version
	// No need for error check, just read it any way since we won't use them if ssl handshake failed.
	ctx->tls_major_ver = ctx->server_connection_tls->tls_eng.ssl.major_ver;
	ctx->tls_minor_ver = ctx->server_connection_tls->tls_eng.ssl.minor_ver;

	// Shutdown ssl session and take over the connection
	tls_shutdown(ctx);

	if (status)
	{
		fprintf(stderr, "TLS handshake error!\n");
		context_close(ctx);
		return;
	}

	Q_DEBUG_MSG("TLS handshake success!");

	if (uv_read_start((uv_stream_t*)ctx->server_connection, alloc_buffer, receive_server))
	{
		fprintf(stderr, "uv_read_start on server_connection error!\n");
		context_close(ctx);
		return;
	}

	if (uv_read_start((uv_stream_t*)ctx->client_connection, alloc_buffer, receive_client))
	{
		fprintf(stderr, "uv_read_start on client_connection error!\n");
		context_close(ctx);
		return;
	}
}

static void on_connect(uv_connect_t* req, int status) {
	uv_stream_t* tcp = req->handle;
	quilt_ctx* ctx = (quilt_ctx*)tcp->data;

	free(req);

	if (status)
	{
		fprintf(stderr, "TCP connection error %s\n", uv_strerror(status));
		context_close(ctx);
		return;
	}

	Q_DEBUG_MSG("Connected!");

	uv_tls_t *client = (uv_tls_t*)malloc(sizeof *client);
	if (uv_tls_init((uv_tcp_t*)tcp, client)) {
		free(client);
		fprintf(stderr, "TLS setup error\n");

		context_close(ctx);
		return;
	}

	ctx->server_connection_tls = client;
	client->data = ctx;
	// Inject out own random function
	client->random_cb = quilt_random;

	if(uv_tls_handshake(client, ctx->config->mocking_host, on_handshake))
	{
		tls_shutdown(ctx);
		context_close(ctx);
	}
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
		quilt_ctx* ctx = (quilt_ctx*)malloc(sizeof(quilt_ctx));
		context_init(ctx);
		ctx->config = config;
		client->data = ctx;
		ctx->client_connection = client;

		// Connect to server
		uv_connect_t *connect_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
		uv_tcp_t *socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(server->loop, socket);
		ctx->server_connection = socket;
		socket->data = ctx;

		if (uv_ext_resolve_connect(connect_req, socket, ctx->config->server_host, ctx->config->server_port, on_connect))
		{
			free(connect_req);
			context_close(ctx);
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

int main(int argc, char** argv) {
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

	fprintf(stderr, "Listen on 127.0.0.1:%d\n", config.local_port);

	int rv = uv_run(loop, UV_RUN_DEFAULT);

	uv_signal_stop(&sigterm);
	uv_signal_stop(&sigint);

	return rv;
}
