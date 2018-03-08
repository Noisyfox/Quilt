#include <stdio.h>
#include <stdlib.h>

#include "uv.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#include "uv_tls.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOST "www.noisyfox.io"
#define PORT 443

#define GET_REQUEST "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"

//typedef struct {
//	uv_write_t req;
//	uv_buf_t buf;
//} write_req_t;
//
//void on_close(uv_handle_t* peer) {
//	free(peer);
//	fprintf(stderr, "Closed ok!\n");
//}
//
//void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
//	*buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
//}
//
//void receive_response(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
//	if (nread < 0) {
//		/* Error or EOF */
//		uv_close((uv_handle_t*)stream, on_close);
//	}
//	else if (nread > 0) {
//		fwrite(buf->base, sizeof(char), nread, stdout);
//	}
//
//	if (buf->base)
//		free(buf->base);
//}
//
//void on_send(uv_write_t* req, int status) {
//	write_req_t* rq = (write_req_t*)req;
//
//	uv_stream_t* tcp = req->handle;
//
//	free(rq->buf.base);
//	free(rq);
//
//	if (status == 0) {
//		fprintf(stderr, "Write ok!\n");
//		uv_read_start(tcp, alloc_buffer, receive_response);
//	}
//	else {
//		fprintf(stderr, "Write error!");
//		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));
//		if (!uv_is_closing((uv_handle_t*)tcp)) {
//			uv_close((uv_handle_t*)tcp, on_close);
//		}
//	}
//}
//
//void on_connect(uv_connect_t* req, int status) {
//	fprintf(stderr, "Connected!");
//
//	uv_stream_t* tcp = req->handle;
//
//	uv_tls_t* clnt = (uv_tls_t*)req->handle->data;
//
//	//write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
//	//char* request_data = _strdup(GET_REQUEST);
//	//rq->buf = uv_buf_init(request_data, strlen(request_data));
//	//uv_write(&rq->req, tcp, &rq->buf, 1, on_send);
//}
//
//int main(){
//	uv_loop_t *loop = uv_default_loop();
//
//	uv_tls_t *client = (uv_tls_t*)malloc(sizeof *client);
//	if (uv_tls_init(loop, client) < 0) {
//		free(client);
//		client = 0;
//		fprintf(stderr, "TLS setup error\n");
//		return  -1;
//	}
//
//	uv_connect_t req;
//	uv_tls_connect(&req, client, HOST, PORT, on_connect);
//
//	uv_run(loop, UV_RUN_DEFAULT);
//
//	tls_engine_stop(&client->tls_eng);
//	free(client);
//	client = 0;
//
//	return 0;
//}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define HOST "www.noisyfox.io"
#define PORT 443

#define GET_REQUEST "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

void on_close(uv_handle_t* peer) {
	free(peer);
	fprintf(stderr, "Closed ok!\n");
}

void on_tls_close(uv_tls_t* h) {
	free(h);
	fprintf(stderr, "TLS closed ok!\n");
}

//void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
//	*buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
//}
//
//void receive_response(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
//	if (nread < 0) {
//		/* Error or EOF */
//		uv_close((uv_handle_t*)stream, on_close);
//	}
//	else if (nread > 0) {
//		fwrite(buf->base, sizeof(char), nread, stdout);
//	}
//
//	if (buf->base)
//		free(buf->base);
//}
//
//void on_send(uv_write_t* req, int status) {
//	write_req_t* rq = (write_req_t*)req;
//
//	uv_stream_t* tcp = req->handle;
//
//	free(rq->buf.base);
//	free(rq);
//
//	if (status == 0) {
//		fprintf(stderr, "Write ok!\n");
//		uv_read_start(tcp, alloc_buffer, receive_response);
//	}
//	else {
//		fprintf(stderr, "Write error!");
//		fprintf(stderr, "uv_write error: %s - %s\n", uv_err_name(status), uv_strerror(status));
//		if (!uv_is_closing((uv_handle_t*)tcp)) {
//			uv_close((uv_handle_t*)tcp, on_close);
//		}
//	}
//}















void on_handshake(uv_tls_t* h, int status)
{
	if(status)
	{
		fprintf(stderr, "TLS handshake error!\n");
		uv_tls_close(h, on_tls_close);
		return;
	}

	fprintf(stderr, "TLS handshake success!\n");
	uv_tls_close(h, on_tls_close);

	//write_req_t *rq = (write_req_t*)malloc(sizeof(write_req_t));
	//char* request_data = _strdup(GET_REQUEST);
	//rq->buf = uv_buf_init(request_data, strlen(request_data));
	//uv_write(&rq->req, tcp, &rq->buf, 1, on_send);
}

void on_connect(uv_connect_t* req, int status) {
	fprintf(stderr, "Connected!");

	uv_stream_t* tcp = req->handle;

	free(req);

	if (status)
	{
		fprintf(stderr, "TCP connection error\n");
		uv_close((uv_handle_t*)tcp, on_close);
		return;
	}

	uv_tls_t *client = (uv_tls_t*)malloc(sizeof *client);
	if (uv_tls_init((uv_tcp_t*)tcp, client)) {
		free(client);
		fprintf(stderr, "TLS setup error\n");

		uv_close((uv_handle_t*)tcp, on_close);
		return;
	}

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
