#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "uv_tls.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOST "www.noisyfox.io"
#define PORT 443

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
	quilt_random_state rnd_state;
} quilt_ctx;

static int quilt_fill_random(quilt_ctx* ctx, unsigned char *output)
{
	int rv;
	// Generate iv
	if ((rv = mbedtls_ctr_drbg_random(&ctx->client->tls_eng.ctr_drbg, output, 16)))
	{
		return rv;
	}
	mbedtls_time_t t = mbedtls_time(NULL);

	return calculate_random(output, PSK, (long)(t / 60 / 60), output + 16);
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
	free(peer);
	fprintf(stderr, "Closed ok!\n");
}

void on_tls_close(uv_tls_t* h) {
	if (h->data) {
		free(h->data);
	}
	free(h);
	fprintf(stderr, "TLS closed ok!\n");
}

void receive_response(uv_tls_t* h, int nread, uv_buf_t* buf) {
//	fprintf(stderr, "receive_response!");
	if (nread < 0) {
		/* Error or EOF */
		uv_tls_close(h, on_tls_close);
	}
	else {
		fwrite(buf->base, sizeof(char), nread, stdout);
	}
}

void on_send(uv_write_t* req, int status) {
	write_req_t* rq = (write_req_t*)req;

	uv_stream_t* tcp = req->handle;

	free(rq->buf.base);
	free(rq);

	if (status == 0) {
		fprintf(stderr, "Write ok!\n");
//		uv_read_start(tcp, alloc_buffer, receive_response);
	}
	else {
		fprintf(stderr, "Write error!");
		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));
		// TODO: somehow close the connection
		//if (!uv_is_closing((uv_handle_t*)tcp)) {
		//	uv_close((uv_handle_t*)tcp, on_close);
		//}
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

	uv_tls_read(h, receive_response);

//	uv_tls_close(h, on_tls_close);

	write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
	char* request_data = _strdup(GET_REQUEST);
	rq->buf = uv_buf_init(request_data, strlen(request_data));
	uv_tls_write(&rq->req, h, &rq->buf, on_send);
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

	ctx->client = client;
	ctx->rnd_state = Q_RND_INIT;

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
	int r = uv_getaddrinfo(loop, &resolver, on_resolved, HOST, STR(PORT), &hints);

	if (r) {
		fprintf(stderr, "getaddrinfo call error %s\n", uv_err_name(r));
		return 1;
	}

	return uv_run(loop, UV_RUN_DEFAULT);
}
