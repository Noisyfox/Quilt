
/*//////////////////////////////////////////////////////////////////////////////

 * Copyright (c) 2015 libuv-tls contributors

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
**////////////////////////////////////////////////////////////////////////////*/


#ifndef __UV_TLS_H__
#define __UV_TLS_H__

#ifdef __cplusplus
extern "C" {
#endif


#include "uv.h"
#include "stdio.h"
#include "stdlib.h"
//#include "unistd.h"
#include "assert.h"
//#include "defs.h"
//#include "sys/socket.h"
#include "stdlib.h"
#include "tls_engine.h"

typedef struct uv_tls_s uv_tls_t;

typedef void (*tls_rd_cb)(uv_tls_t* h, int nrd, uv_buf_t* dcrypted);
typedef void (*tls_sd_cb)(uv_tls_t* h, int status);
typedef void (*tls_close_cb)(uv_tls_t* h);
typedef void (*tls_handshake_cb)(uv_tls_t* h, int status);
typedef int(*tls_random_cb)(uv_tls_t* h, unsigned char *output, size_t output_len);

//Most used members are put first
struct uv_tls_s {
    uv_tcp_t*             socket_; //handle that encapsulate the socket
    tls_engine            tls_eng;  //the tls engine representation
    void                  *data;
    int                   oprn_state; // operational state
    tls_rd_cb             rd_cb;
    tls_close_cb          close_cb;
	tls_handshake_cb      handshake_cb;
	tls_random_cb         random_cb;
};


/*
 *Initialize the common part of SSL startup both for client and server
 Only uv_tls_init at max will return TLS engine related issue other will have
 libuv error
 */
int uv_tls_init(uv_tcp_t* connection, uv_tls_t* client);
int uv_tls_read(uv_tls_t* client, tls_rd_cb cb);
int uv_tls_write(uv_write_t* req, uv_tls_t* client, uv_buf_t* buf, uv_write_cb cb);

int uv_tls_close(uv_tls_t* session, tls_close_cb cb);
//shutdown should go away
int uv_tls_shutdown(uv_tls_t* session);

int uv_tls_handshake(uv_tls_t* h, const char *host, tls_handshake_cb cb);

#ifdef __cplusplus
}
#endif

#endif 
