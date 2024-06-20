/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <netinet/in.h>
#include <unistd.h>
#include <assert.h>
#include <nghttp3/nghttp3.h>

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof((NAME)) - 1,                 \
        sizeof((VALUE)) - 1, NGHTTP3_NV_FLAG_NONE                              \
  }         
#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* CURL according to trace has 2 more streams 7 and 11 */
struct ssl_id {
  SSL *s;
  uint64_t id;
};

#define MAXSSL_IDS 20
struct h3ssl {
   struct ssl_id ssl_ids[MAXSSL_IDS];
   int end_headers_received;
   int datadone;
};

static void init_id(struct h3ssl *h3ssl)
{
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    ssl_ids[i].s = NULL;
    ssl_ids[i].id = -1;
  }
  h3ssl->end_headers_received = 0;
  h3ssl->datadone = 0;
}

static void add_id(uint64_t id, SSL *ssl, struct h3ssl *h3ssl) {
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (!ssl_ids[i].s) {
      ssl_ids[i].s = ssl;
      ssl_ids[i].id = id;
      return;
    }
  }
  printf("Oops too many streams to add!!!\n");
  exit(1);
}
static void closeall(struct h3ssl *h3ssl) {
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].s) {
        SSL_stream_conclude(ssl_ids[i].s, 0);
    }
  }
}
static void h3close(struct h3ssl *h3ssl, uint64_t id) {
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].id == id) {
        SSL_stream_conclude(ssl_ids[i].s, 0);
        SSL_shutdown(ssl_ids[i].s);
    }
  }
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                             uint64_t datalen, void *user_data,
                             void *stream_user_data) {
    printf("cb_h3_acked_req_body!\n");
    return 0;
}
static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
    printf("cb_h3_stream_close!\n");
    return 0;
}
static int begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                         void *stream_user_data) {
    printf("begin_headers!\n");
    return 0;
}
static int cb_h3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_begin_headers!\n");
    return 0;
}
static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                       nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                       void *user_data, void *stream_user_data) {
    printf("cb_h3_recv_header!\n");
    return 0;
}
static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                       void *user_data, void *stream_user_data) {

    printf("cb_h3_end_headers!\n");
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;
    h3ssl->end_headers_received = 1;
    return 0;
}
static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                                 const uint8_t *data, size_t datalen,
                                 void *conn_user_data, void *stream_user_data) {
    printf("cb_h3_recv_data! %d\n", datalen);
    printf("cb_h3_recv_data! %.*s\n", datalen, data);
    return 0;
}
static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
    printf("cb_h3_deferred_consume!\n");
    return 0;
}
static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
    printf("cb_h3_stop_sending!\n");
    return 0;
}
static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
    printf("cb_h3_reset_stream!\n");
    return 0;
}
static int cb_h3_shutdown(nghttp3_conn *conn, int64_t id, void *conn_user_data) {
    printf("cb_h3_shutdown!\n");
    return 0;
}
static int cb_h3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings, void *conn_user_data) {
    printf("cb_h3_recv_settings!\n");
    return 0;
}
static int cb_h3_begin_trailers() {
    printf("cb_h3_begin_trailers!\n");
    return 0;
}
static int cb_h3_end_trailers() {
    printf("cb_h3_end_trailers!\n");
    return 0;
}
static int cb_h3_end_stream() {
    printf("cb_h3_end_stream!\n");
    return 0;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  cb_h3_begin_headers, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  cb_h3_begin_trailers, /* begin_trailers */
  cb_h3_recv_header,
  cb_h3_end_trailers, /* end_trailers */
  cb_h3_stop_sending,
  cb_h3_end_stream, /* end_stream */
  cb_h3_reset_stream,
  cb_h3_shutdown, /* shutdown */
  cb_h3_recv_settings /* recv_settings */
};

static int read_from_ssl_ids(nghttp3_conn *conn, struct h3ssl *h3ssl)
{
  char msg2[16000];
  int hassomething = 0;
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].s) {
      /* try to read */
      int ret = 0;
      size_t l = sizeof(msg2) - 1;
      if (SSL_net_read_desired(ssl_ids[i].s)) {
         ret = SSL_read(ssl_ids[i].s, msg2, l);
      } else {
         continue;
      }   
      if (ret <= 0) {
         printf("ossl_quic_tserver_read on %d failed\n", ssl_ids[i].id);
        continue; // TODO
      } else { 
           printf("\nreading something %d on %d\n", ret, ssl_ids[i].id);
           int r = nghttp3_conn_read_stream(conn, ssl_ids[i].id, msg2, ret, 0);
           printf("nghttp3_conn_read_stream used %d of %d on %d\n", r, ret, ssl_ids[i].id);
           hassomething++;
      }             
    }           
  }
  return hassomething;
}

/* The crappy test wants 20 bytes */
static uint8_t nulldata[20] = "12345678901234567890";
static int datadone = 0;
static nghttp3_ssize step_read_data(nghttp3_conn *conn, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data)
{           
  struct h3ssl *h3ssl = (struct h3ssl *)user_data;
  if (h3ssl->datadone) {
      *pflags = NGHTTP3_DATA_FLAG_EOF;
      return 0;
  }         
  vec[0].base = nulldata;
  vec[0].len = 20;
  h3ssl->datadone++;
                
  return 1;     
}           

static int quic_server_write(struct h3ssl *h3ssl, uint64_t streamid, char *buff , int len, uint64_t flags, size_t *written)
{
  struct ssl_id *ssl_ids;
  ssl_ids = h3ssl->ssl_ids;
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].id == streamid) {
      if (!SSL_write_ex2(ssl_ids[i].s, buff, len, flags, written)
          || *written !=len) {
        fprintf(stderr, "couldn't write on connection\n");
        ERR_print_errors_fp(stderr);
        return 0;
      } else {
        printf("written %d on %d flags %d\n", len, streamid, flags);
        return 1;
      }
    }
  }
  printf("quic_server_write %d on %d (NOT FOUND!)\n", len, streamid);
  return 0;
}

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

/*
 * This is a basic demo of QUIC server functionality in which one connection at
 * a time is accepted in a blocking loop.
 */

/* ALPN string for TLS handshake */
static const unsigned char alpn_ossltest[] = {
    /* "\x08ossltest" (hex for EBCDIC resilience) */
    /* 0x08, 0x6f, 0x73, 0x73, 0x6c, 0x74, 0x65, 0x73, 0x74 */
    5, 'h', '3', '-', '2', '9', 2, 'h', '3'
};

/* This callback validates and negotiates the desired ALPN on the server side. */
static int select_alpn(SSL *ssl,
                       const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len,
                       void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len,
                              alpn_ossltest, sizeof(alpn_ossltest), in, in_len)
            != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "private key check failed\n");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket using given port. */
static int create_socket(uint16_t port)
{
    int fd = -1;
    struct sockaddr_in sa = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "cannot create socket");
        goto err;
    }

    sa.sin_family  = AF_INET;
    sa.sin_port    = htons(port);

    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "cannot bind to %u\n", port);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}

/* Main loop for servicing a single incoming QUIC connection. */
static int run_quic_conn(SSL *conn)
{
    size_t written = 0;

    fprintf(stderr, "=> Received connection\n");
    fprintf(stderr, "=> Received connection on %ld\n", SSL_get_stream_id(conn));
    fflush(stdout);

    /*
     * Write the message "hello" on the connection using a default stream
     * and then immediately conclude the stream (end-of-stream). This
     * demonstrates the use of SSL_write_ex2 for optimised FIN generation.
     *
     * Since we inherit our blocking mode from the parent QUIC SSL object (the
     * listener) by default, this call is also blocking.
     */
    if (!SSL_write_ex2(conn, "hello\n", 6, SSL_WRITE_FLAG_CONCLUDE, &written)
        || written != 6) {
        fprintf(stderr, "couldn't write on connection\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Shut down the connection (blocking). */
    if (SSL_shutdown(conn) != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    fprintf(stderr, "=> Finished with connection\n");
    return 1;
}

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(SSL_CTX *ctx, int fd)
{
    int ok = 0;
    SSL *listener = NULL, *conn = NULL;

    /* Create a new QUIC listener. */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    /* Provide the listener with our UDP socket. */
    if (!SSL_set_fd(listener, fd))
        goto err;

    /* Begin listening. */
    if (!SSL_listen(listener))
        goto err;

    /*
     * Listeners, and other QUIC objects, default to operating in blocking mode,
     * so the below call is not actually necessary. The configured behaviour is
     * inherited by child objects.
     */
    SSL_set_blocking_mode(listener, 1);
    // SSL_set_event_handling_mode(listener,SSL_VALUE_EVENT_HANDLING_MODE);

    for (;;) {
        SSL_POLL_ITEM items[5] = {0}, *item = items;
        static const struct timeval nz_timeout = {0, 0};
        size_t result_count = SIZE_MAX;
        /* Blocking wait for an incoming connection, similar to accept(2). */
        fprintf(stderr, "before SSL_accept_connection\n");
        fflush(stderr);
        conn = SSL_accept_connection(listener, 0);
        fprintf(stderr, "after SSL_accept_connection\n");
        fflush(stderr);
        if (conn == NULL) {
            fprintf(stderr, "error while accepting connection\n");
            goto err;
        }
        SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

   /* try to use nghttp3 to send a response */
    nghttp3_conn *h3conn;
    nghttp3_settings settings;
    nghttp3_callbacks callbacks;
    struct h3ssl h3ssl;
    
    const nghttp3_mem *mem = nghttp3_mem_default();
    init_id(&h3ssl); 
    nghttp3_settings_default(&settings);
    if (nghttp3_conn_server_new(&h3conn, &ngh3_callbacks, &settings, mem, &h3ssl)) {
        printf("nghttp3_conn_client_new failed!\n"); 
        exit(1);
    }       
    printf("process_server starting...\n");
    fflush(stdout);

        /*
         * Optionally, we could disable blocking mode on the accepted connection
         * here by calling SSL_set_blocking_mode().
         */

        /*
         * Service the connection. In a real application this would be done
         * concurrently. In this demonstration program a single connection is
         * accepted and serviced at a time.
         */
        // SSL *stream = SSL_get0_listener(conn);
        int numstream = 0;
more:
        SSL *stream = SSL_accept_stream(conn, 0);
        if (stream != NULL) {
           fprintf(stderr, "=> Received connection on %ld\n", SSL_get_stream_id(stream));
           fflush(stderr);
           add_id(SSL_get_stream_id(stream), stream, &h3ssl);
           numstream++;
           if (numstream==4) {
               numstream = 0;
               goto openstreams;
           }
           goto more;
        } else {
           fprintf(stderr, "=> Stream == NULL!\n");
           fflush(stderr);
           goto err;
        }
openstreams:
        /* we have 4 streams from the client 2, 6 , 10 and 0 */ 
        /* need 2 streams to the client */
        SSL *rstream = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
        if (rstream != NULL) {
           fprintf(stderr, "=> Opened on %ld\n", SSL_get_stream_id(rstream));
           fflush(stderr);
        } else {
           fprintf(stderr, "=> Stream == NULL!\n");
           fflush(stderr);
           goto err;
        }
        SSL *pstream = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
        if (pstream != NULL) {
           fprintf(stderr, "=> Opened on %ld\n", SSL_get_stream_id(pstream));
           fflush(stderr);
        } else {
           fprintf(stderr, "=> Stream == NULL!\n");
           fflush(stderr);
           goto err;
        }
        uint64_t r_streamid = SSL_get_stream_id(rstream);
        uint64_t p_streamid = SSL_get_stream_id(pstream);
        if (nghttp3_conn_bind_qpack_streams(h3conn, p_streamid, r_streamid)) {
            printf("nghttp3_conn_bind_qpack_streams failed!\n");
            exit(1);
        }
        printf("control: NONE enc %d dec %d\n", p_streamid, r_streamid);
        add_id(SSL_get_stream_id(rstream), rstream, &h3ssl);
        add_id(SSL_get_stream_id(pstream), pstream, &h3ssl);

trynext:
        while (!h3ssl.end_headers_received) {
            int hassomething = read_from_ssl_ids(h3conn, &h3ssl);
            if (!hassomething) {
                printf("!hassomething\n"); 
                goto err;
            }
        }
        printf("end_headers_received!!!\n");

       /* we have receive the request build response and send it */
       /*     MAKE_NV("connection", "close"), */
        nghttp3_nv resp[] = {
            MAKE_NV(":status", "200"),
            MAKE_NV("content-length", "20"),
        };
        nghttp3_data_reader dr;
        dr.read_data = step_read_data;
        if (nghttp3_conn_submit_response(h3conn, 0, resp, 2, &dr)) {
            printf("nghttp3_conn_submit_response failed!\n");
            goto err;
        }
        printf("nghttp3_conn_submit_response...\n");
        for (;;) {
            nghttp3_vec vec[256];
            nghttp3_ssize sveccnt;
            int fin;
            uint64_t streamid;
            sveccnt = nghttp3_conn_writev_stream(h3conn, &streamid, &fin, vec, nghttp3_arraylen(vec));
            if (sveccnt <= 0) {
                printf("nghttp3_conn_writev_stream done: %d\n", sveccnt);
                break;
            } else {
                printf("nghttp3_conn_writev_stream: %d\n", sveccnt);
            }
            for (int i=0; i<sveccnt; i++) {
                printf("quic_server_write on %d for %d\n", streamid, vec[i].len);
                size_t numbytes = vec[i].len ;
                if (!quic_server_write(&h3ssl, streamid, vec[i].base , vec[i].len, fin, &numbytes)) {
                    printf("quic_server_write failed!\n");
                    goto err;
                }
            }
            if (nghttp3_conn_add_write_offset(h3conn, streamid, (size_t)nghttp3_vec_len(vec, (size_t)sveccnt))) {
                printf("nghttp3_conn_add_write_offset failed!\n");
                goto err;
            }
        }
        printf("nghttp3_conn_submit_response DONE!!!\n");

        if (h3ssl.datadone) {
            // All the data was sent.
            // closeall(&h3ssl);
            // SSL_shutdown(conn);
            // close stream zero
            h3close(&h3ssl, 0);
            // sleep(10);
        }

        /* Free the connection, then loop again, accepting another connection. */
        SSL_free(conn);
    }

    ok = 1;
err:
    if (!ok)
        ERR_print_errors_fp(stderr);

    SSL_free(listener);
    return ok;
}

int main(int argc, char **argv)
{
    int rc = 1;
    SSL_CTX *ctx = NULL;
    int fd = -1;
    unsigned long port;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <server.crt> <server.key>\n", argv[0]);
        goto err;
    }

    /* Create SSL_CTX. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL)
        goto err;

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %lu\n", port);
        goto err;
    }

    /* Create UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0)
        goto err;

    /* Enter QUIC server connection acceptance loop. */
    if (!run_quic_server(ctx, fd))
        goto err;

    rc = 0;
err:
    if (rc != 0)
        ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);

    if (fd != -1)
        BIO_closesocket(fd);

    return rc;
}
