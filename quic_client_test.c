/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <apr-1/apr_time.h>

#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nghttp3/nghttp3.h>

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof((NAME)) - 1,                 \
        sizeof((VALUE)) - 1, NGHTTP3_NV_FLAG_NONE                              \
  }

static const char msg1[] = "GET / HTTP/3\r\nHost: quic.rocks:4433\r\n\r\n";
static char msg2[16000];

/* CURL according to trace has 2 more streams 7 and 11 */
struct ssl_id {
  SSL *s;
  int64_t id;
};

#define MAXSSL_IDS 20
static struct ssl_id ssl_ids[MAXSSL_IDS];

static void init_id()
{
  for (int i=0; i<MAXSSL_IDS; i++) {
    ssl_ids[i].s = NULL;
    ssl_ids[i].id = -1;
  }
}

static void add_id(SSL *s) {
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (!ssl_ids[i].s) {
      ssl_ids[i].s = s;
      ssl_ids[i].id = SSL_get_stream_id(s);
      return;
    }
  }
  printf("Oops too many streams to add!!!\n");
  exit(1);
}

static SSL *get_ssl_from_id(int64_t id)
{
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].id == id) {
      return ssl_ids[i].s;
    }
  }
  return NULL;
}

/* Accept the new QUIC stream opened by the other side */
static void accept_new_ssl_ids(SSL *s,  BIO *bio) {
  int num = SSL_get_accept_stream_queue_len(s);
  if (num > 0) {
    for (int i=0; i<num; i++) {
      SSL *new_ssl = SSL_accept_stream(s, 0);
      if (new_ssl) {
          printf("accept_new_ssl_ids accepted: SSL_get_stream_id: %d %d\n", SSL_get_stream_id(new_ssl), SSL_get_stream_type(new_ssl));
          add_id(new_ssl);
          SSL_set_msg_callback(new_ssl, SSL_trace);
          SSL_set_msg_callback_arg(new_ssl, bio);
      } else {
          printf("accept_new_ssl_ids NULL, weird\n");
      }
    }
  }
}

static void TEST_info(char *fmt, ...)                                                       
{                                                                               
   va_list arg_ptr;                                                             
                                                                                
   va_start(arg_ptr, fmt);                                                      
   vprintf(fmt, arg_ptr);                                                       
   va_end(arg_ptr);                                                             
}
#define TEST_error TEST_info

static int is_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);

    return ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE;
}

/* Read and process the data for the ids we have */
static int read_from_ssl_ids(nghttp3_conn *conn)
{
  for (int i=0; i<MAXSSL_IDS; i++) {
    if (ssl_ids[i].s) {
      /* try to read */
      size_t l = sizeof(msg2) - 1;
      int ret = SSL_read_ex(ssl_ids[i].s, msg2, sizeof(msg2) - 1, &l);
      if (ret <= 0) {
        if (SSL_get_error(ssl_ids[i].s, ret) == SSL_ERROR_ZERO_RETURN) {
             printf("\n SSL_read_ex FAILED! c_shutdown\n");
             return -1;
         } else if (!(is_want(ssl_ids[i].s, ret))) {
             // Vebose ... printf("\n SSL_read_ex FAILED %d stream: %d!\n", SSL_get_error(ssl_ids[i].s, ret), SSL_get_stream_id(ssl_ids[i].s));
             fflush(stdout);
             continue; // TODO
         }
      } else {
        printf("\nreading something %d on %d\n", l, SSL_get_stream_id(ssl_ids[i].s));
        int r = nghttp3_conn_read_stream(conn, SSL_get_stream_id(ssl_ids[i].s), msg2, l, 0);
        printf("nghttp3_conn_read_stream used %d of %d on %d\n", r, l, SSL_get_stream_id(ssl_ids[i].s));
      }
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
    nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);

    if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
        printf("Status %.*s\n", h3val.len, h3val.base);
    } else {
        printf("header %.*s: %.*s\n",  (int)h3name.len, h3name.base, (int)h3val.len, h3val.base);
    }    
    return 0;
}
static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                       void *user_data, void *stream_user_data) {

    printf("cb_h3_end_headers!\n");
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


static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  cb_h3_begin_headers, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  cb_h3_stop_sending,
  NULL, /* end_stream */
  cb_h3_reset_stream,
  cb_h3_shutdown, /* shutdown */
  cb_h3_recv_settings /* recv_settings */
};

static int jfc_send_stream(SSL *M_ssl, int ret, nghttp3_vec *vec)
{
    int i;
    int written = 0;
    for (i=0; i<ret; i++) {
       printf("jfc_send_stream writting %d on %d\n", vec[i].len, SSL_get_stream_id(M_ssl));
       int rv = SSL_write(M_ssl, vec[i].base, vec[i].len);
       if (rv<=0)
           printf("SSL_write failed! %d\n", SSL_get_error(M_ssl, rv));
       written = written + vec[i].len;
    }
    return written;
}

/* Send everything we can */
static void send_all_stream(nghttp3_conn *conn)
{
    for (;;) {
        int64_t stream_id = 0;
        int fin = 0;
        nghttp3_vec vec[256];
        int ret = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 256);
        if (ret<0) {
            printf("nghttp3_conn_writev_stream failed %d!\n", ret);
            exit(1);
        } else if (ret == 0 && stream_id == -1) {
            // Too verbose printf("Done with nghttp3_conn_writev_stream\n");
            fflush(stdout);
            break;
        } else if (ret == 0 && stream_id != -1) {
            printf("Done with nghttp3_conn_writev_stream on %d fin: %d\n", stream_id, fin);
            nghttp3_conn_add_write_offset(conn, stream_id, 0);
            break;
        } else {
            /* We have to write the vec stuff */
            printf("sending %d on %d (fin: %d)\n", ret, stream_id, fin);
            SSL *MY_ssl = get_ssl_from_id(stream_id);
            if (!MY_ssl) {
                 printf("stream_id: %d unknown\n", stream_id);
                 exit(1);
            }

            int i = jfc_send_stream(MY_ssl, ret, vec);

            if (i != 0) {
                nghttp3_conn_add_write_offset(conn, stream_id, i);
                printf("sending %d on %d (fin: %d)\n", ret, stream_id, fin);
                if (fin) {
                    printf("FIN on %d\n", stream_id);
                    SSL_stream_conclude(MY_ssl, 0);
                }
                continue;
            } else {
                printf("sending NOTHING %d on %d (fin: %d)\n", ret, stream_id, fin);
            }
        }
    }
}

static int test_quic_client(char *hostname, short port)
{
    int testresult = 0, ret;
    int c_fd = -1;
    BIO *c_net_bio = NULL;
    BIO *c_net_bio_own = NULL;
    BIO_ADDR *s_addr_ = NULL;
    struct in_addr ina = {0};
    SSL_CTX *c_ctx = NULL;
    SSL *c_ssl = NULL;
    int c_connected = 0, c_write_done = 0, c_shutdown = 0;
    size_t l = 0, c_total_read = 0;
    apr_time_t start_time;
    /* unsigned char alpn[] = { 8, 'h', 't', 't', 'p', '/', '0', '.', '9' }; lol */
    unsigned char alpn[] = { 5, 'h', '3', '-', '2', '9', 2, 'h', '3' };

    struct hostent *hp;

    /* try to use nghttp3 to build a get request */
    nghttp3_conn *conn;
    nghttp3_settings settings;
    nghttp3_callbacks callbacks;
    nghttp3_vec vec[256];
    int64_t stream_id;
    // userdata ud;
    char ud[10];
    int fin;
    const nghttp3_mem *mem = nghttp3_mem_default();
    const nghttp3_nv nva[] = {
      MAKE_NV(":path", "/"),
      MAKE_NV(":authority", "quic.rocks:4433"),
      MAKE_NV(":scheme", "https"),
      MAKE_NV(":method", "GET"),
      MAKE_NV("user-agent", "curl/8.2.0-DEV"),
      MAKE_NV("accept", "*/*"),
    };

    init_id();
    nghttp3_settings_default(&settings);
    memset(&ud, 0, sizeof(ud));
    if (nghttp3_conn_client_new(&conn, &ngh3_callbacks, &settings, mem, &ud)) {
        printf("nghttp3_conn_client_new failed!\n");
        exit(1);
    }

    hp = gethostbyname(hostname);
    if (hp == NULL)
        goto err;

    memcpy(&ina,hp->h_addr,hp->h_length);
    printf("Connecting to %s:%d\n",  inet_ntoa(ina), port);

    TEST_info("Before: BIO_socket\n");
    c_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (c_fd == -1)
        goto err;

    if (!BIO_socket_nbio(c_fd, 1))
        goto err;

    s_addr_ = BIO_ADDR_new();
    if (s_addr_ == NULL)
        goto err;

    TEST_info("Before: BIO_ADDR_rawmake\n");
    if (!(BIO_ADDR_rawmake(s_addr_, AF_INET, &ina, sizeof(ina),
                                    htons(port)))) {
        TEST_error("BIO_ADDR_rawmake failed!\n");
        goto err;
    }

    c_net_bio_own = BIO_new_dgram(c_fd, 0);
    c_net_bio = c_net_bio_own;
    if (c_net_bio == NULL)
        goto err;

    if (!BIO_dgram_set_peer(c_net_bio, s_addr_))
        goto err;

    c_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (c_ctx == NULL)
        goto err;

    /* Enable trust chain verification. */
    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_PEER, NULL);

    /* Load default root CA store. */
    if (!SSL_CTX_load_verify_locations(c_ctx, "/etc/pki/CA/cacert.pem" , "/etc/ssl/certs")) {
        goto err;
    }
/* problems ...
    if (SSL_CTX_set_default_verify_paths(c_ctx) == 0) {
        goto err;
    }
 */

    c_ssl = SSL_new(c_ctx);
    if (c_ssl == NULL)
        goto err;

    /* SSL_set_tlsext_host_name(c_ssl, hostname); /0 JFC add */

    /* SSL_CTX_set_session_id_context missing ? */
    /*
    int session_id_context = -1;
    SSL_CTX_set_session_id_context(c_ctx, (void *)&session_id_context, sizeof(session_id_context));
     */

    /* 0 is a success for SSL_set_alpn_protos() */
    if (SSL_set_alpn_protos(c_ssl, alpn, sizeof(alpn)))
        goto err;

    /* Takes ownership of our reference to the BIO. */
    SSL_set0_rbio(c_ssl, c_net_bio);

    /* Get another reference to be transferred in the SSL_set0_wbio call. */
    if (!(BIO_up_ref(c_net_bio))) {
        c_net_bio_own = NULL; /* SSL_free will free the first reference. */
        goto err;
    }

    SSL_set0_wbio(c_ssl, c_net_bio);
    c_net_bio_own = NULL;

    if (!(SSL_set_blocking_mode(c_ssl, 0)))
        goto err;

    start_time = apr_time_now();

    // SSL_set_default_stream_mode(c_ssl, SSL_DEFAULT_STREAM_MODE_NONE);
    // SSL_set_default_stream_mode(c_ssl, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI);
    // SSL_set_incoming_stream_policy(c_ssl, SSL_INCOMING_STREAM_POLICY_AUTO, 0);

    // Try traces
    BIO *bio = BIO_new_file("trace.txt", "w");
    SSL_set_msg_callback(c_ssl, SSL_trace);
    SSL_set_msg_callback_arg(c_ssl, bio);

    for (;;) {
        if (apr_time_now() - start_time >= 60000000) {
            TEST_error("timeout while attempting QUIC client test\n");
            goto err;
        }
        /* Check for new QUIC streams and accept them */
        if (c_ssl) {
            accept_new_ssl_ids(c_ssl, bio);
        }


        if (!c_connected) {
            ret = SSL_connect(c_ssl);
            /* printf("SSL_connect returns %d %d\n", ret, is_want(c_ssl, ret)); */
            if (!(ret == 1 || is_want(c_ssl, ret))) {
                TEST_error("SSL_connect failed!\n");
                goto err;
            }

            if (ret == 1) {
                c_connected = 1;
                TEST_info("Connected!");
                printf("Connected!\n");
                add_id(c_ssl);
            }
        }

        if (c_connected && !c_write_done) {
            printf("sending request...\n");
            SSL *C_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(C_ssl, SSL_trace);
    SSL_set_msg_callback_arg(C_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_type(C_ssl));
            SSL *p_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(p_ssl, SSL_trace);
    SSL_set_msg_callback_arg(p_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(p_ssl), SSL_get_stream_type(p_ssl));
            SSL *r_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
    SSL_set_msg_callback(r_ssl, SSL_trace);
    SSL_set_msg_callback_arg(r_ssl, bio);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(r_ssl), SSL_get_stream_type(r_ssl));

            if (nghttp3_conn_bind_control_stream(conn, SSL_get_stream_id(C_ssl))) {
                printf("nghttp3_conn_bind_control_stream failed!\n");
                exit(1);
            }
            if (nghttp3_conn_bind_qpack_streams(conn, SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl))) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
            }
            printf("control: %d enc %d dec %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl));
            add_id(C_ssl);
            add_id(p_ssl);
            add_id(r_ssl);

            /* send what we can */
            send_all_stream(conn);
            
            printf("SSL_write started!!!\n");

            c_write_done = 1;
            OSSL_sleep(1);

            SSL *d_ssl = SSL_new_stream(c_ssl, 0);
    SSL_set_msg_callback(d_ssl, SSL_trace);
    SSL_set_msg_callback_arg(d_ssl, bio);
            add_id(d_ssl);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(d_ssl), SSL_get_stream_type(d_ssl));
            if (nghttp3_conn_submit_request(conn, SSL_get_stream_id(d_ssl), nva, 6, NULL, NULL)) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
            }

        }

        if (c_write_done && !c_shutdown) {
            ret = read_from_ssl_ids(conn);
            if (ret < 0) {
                printf("\n read_from_ssl_ids() FAILED!!!");
                goto err;
            }
            /* send what we can */
            send_all_stream(conn);
        }

        if (c_shutdown) {
            ret = SSL_shutdown(c_ssl);
            if (ret == 1)
                break;
        }

        /*
         * This is inefficient because we spin until things work without
         * blocking but this is just a test.
         */
        OSSL_sleep(10);
        SSL_handle_events(c_ssl);
    }

    testresult = 1;
err:
    SSL_free(c_ssl);
    SSL_CTX_free(c_ctx);
    BIO_ADDR_free(s_addr_);
    BIO_free(c_net_bio_own);
    if (c_fd != -1)
        BIO_closesocket(c_fd);
    return testresult;
}

/* OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n") */

int main (int argc, char ** argv)
{
    short port;
    if (argc != 3) {
        printf("Usage: ./quic_client_test hostname port !\n");
        exit(1);
    }
    port = atoi(argv[2]);
    if (port<=0) {
        printf("port: %s invalid\n", argv[2]);
        exit(1);
    }
    if (!test_quic_client(argv[1], port))
        printf("\n test_quic_client failed!!!");
    return 1;
}
