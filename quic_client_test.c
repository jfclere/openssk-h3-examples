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
SSL *r1_ssl = NULL;
SSL *r2_ssl = NULL;
SSL *r3_ssl = NULL;

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

static int JFC_SSL_read_ex(SSL *M_ssl)
{
            size_t l = sizeof(msg2) - 1;
            if (SSL_get_accept_stream_queue_len(M_ssl)) {
                printf("SSL_get_accept_stream_queue_len %d\n", SSL_get_accept_stream_queue_len(M_ssl));
                SSL *new_ssl = SSL_accept_stream(M_ssl, 0);
                printf("new_ssl: %d", SSL_get_stream_id(new_ssl));
                if (!r1_ssl)
                    r1_ssl = new_ssl;
                else if (!r2_ssl)
                    r2_ssl = new_ssl;
                else if (!r3_ssl)
                    r3_ssl = new_ssl;
                else {
                    printf("Oops too many streams to accept!!!\n");
                    exit(1);
                }
            }

            int ret = SSL_read_ex(M_ssl, msg2,
                              sizeof(msg2) - 1, &l);
            printf("SSL_read_ex on %d return %d\n", SSL_get_stream_id(M_ssl), ret);
            if (ret <= 0) {
                if (SSL_get_error(M_ssl, ret) == SSL_ERROR_ZERO_RETURN) {
                    printf("\n SSL_read_ex FAILED! c_shutdown\n");
                    return -1;
                } else if (!(is_want(M_ssl, ret))) {
                    // printf("\n SSL_read_ex FAILED %d stream: %d!\n", SSL_get_error(M_ssl, ret), SSL_get_stream_id(M_ssl));
                    return 0;
                }
            } else {
                printf("\nreading something %d on %d\n", l, SSL_get_stream_id(M_ssl));
                return l;
            }
            if (ret == 0 && SSL_get_error(M_ssl, ret)==SSL_ERROR_WANT_READ) {
                printf("Need to read again... on %d\n", SSL_get_stream_id(M_ssl));
                // SSL_set_blocking_mode(M_ssl, 1);
                printf("Need to read again... on %d BLOCKING!!!\n", SSL_get_stream_id(M_ssl));
                // SSL_read_ex(M_ssl, msg2, sizeof(msg2) - 1, &l);
                SSL *new_ssl = SSL_accept_stream(M_ssl, 0);
                if (new_ssl)
                    exit(1);
                else
                    printf("new_ssl: %d\n", new_ssl);
                printf("SSL_get_accept_stream_queue_len %d\n", SSL_get_accept_stream_queue_len(M_ssl));
                // SSL_set_blocking_mode(M_ssl, 0);
                if (l == 0) {
                //     SSL_shutdown(M_ssl);
                    return 0;
                }
            }
            printf("reading something %d\n", l);
            return 0;
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

static int jfc_send_stream(SSL *c_ssl, int ret, nghttp3_vec *vec)
{
    int i;
    int written = 0;
    for (i=0; i<ret; i++) {
       printf("jfc_send_stream writting %d on %d\n", vec[i].len, SSL_get_stream_id(c_ssl));
       int rv = SSL_write(c_ssl, vec[i].base, vec[i].len);
       if (rv<=0)
           printf("SSL_write failed! %d\n", SSL_get_error(c_ssl, rv));
       written = written + vec[i].len;
    }
    return written;
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
    };

    nghttp3_settings_default(&settings);
    memset(&ud, 0, sizeof(ud));
    if (nghttp3_conn_client_new(&conn, &ngh3_callbacks, &settings, mem, &ud)) {
        printf("nghttp3_conn_client_new failed!\n");
        exit(1);
    }
/*
    if (nghttp3_conn_submit_request(conn, 0, nva, 4, NULL, NULL)) {
        printf("nghttp3_conn_bind_qpack_streams failed!\n");
        exit(1);
    }
    ret = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 256);
    if (ret<0) {
        printf("nghttp3_conn_writev_stream failed %d!\n", ret);
        exit(1);
    }
    if (nghttp3_conn_add_write_offset(conn, stream_id, fin)) {
        printf("nghttp3_conn_add_write_offset failed!\n");
        exit(1);
    }
    printf("Done!\n");
    exit(1);
*/

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
    if (!SSL_CTX_load_verify_locations(c_ctx, NULL, "/etc/ssl/certs")) {
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
    SSL *n_ssl = NULL;
    SSL *C_ssl = NULL;
    SSL *p_ssl = NULL;
    SSL *r_ssl = NULL;
    SSL *d_ssl = NULL;

    // SSL_set_default_stream_mode(c_ssl, SSL_DEFAULT_STREAM_MODE_NONE);
    SSL_set_incoming_stream_policy(c_ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

    for (;;) {
        if (apr_time_now() - start_time >= 60000000) {
            TEST_error("timeout while attempting QUIC client test\n");
            goto err;
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
            }
        }

        if (c_connected && !c_write_done) {
            printf("sending request...\n");
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(c_ssl), SSL_get_stream_type(c_ssl));
            C_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_type(C_ssl));
            p_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(p_ssl), SSL_get_stream_type(p_ssl));
            r_ssl = SSL_new_stream(c_ssl, SSL_STREAM_FLAG_UNI);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(r_ssl), SSL_get_stream_type(r_ssl));

            ret = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 256);
            if (ret<0) {
                printf("nghttp3_conn_writev_stream failed %d!\n", ret);
                exit(1);
            } else {
                /* We have to write the vec stuff */
                printf("JFC sending %d on %d (%d)\n", ret, stream_id, fin);
            }

            if (nghttp3_conn_bind_control_stream(conn, SSL_get_stream_id(C_ssl))) {
                printf("nghttp3_conn_bind_control_stream failed!\n");
                exit(1);
            }
            if (nghttp3_conn_bind_qpack_streams(conn, SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl))) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
            }
            printf("control: %d enc %d dec %d\n", SSL_get_stream_id(C_ssl), SSL_get_stream_id(p_ssl), SSL_get_stream_id(r_ssl));

            d_ssl = SSL_new_stream(c_ssl, 0);
            printf("SSL_get_stream_id: %d type: %d\n", SSL_get_stream_id(d_ssl), SSL_get_stream_type(d_ssl));
            if (nghttp3_conn_submit_request(conn, SSL_get_stream_id(d_ssl), nva, 4, NULL, NULL)) {
                printf("nghttp3_conn_bind_qpack_streams failed!\n");
                exit(1);
            }
try_again:
            stream_id = 0;
            fin = 0;
            ret = nghttp3_conn_writev_stream(conn, &stream_id, &fin, vec, 256);
            if (ret<0) {
                printf("nghttp3_conn_writev_stream failed %d!\n", ret);
                exit(1);
            } else {
                /* We have to write the vec stuff */
                printf("sending %d on %d (%d)\n", ret, stream_id, fin);
                SSL *MY_ssl = NULL;
                if (SSL_get_stream_id(n_ssl) == stream_id)
                    MY_ssl = n_ssl;
                if (SSL_get_stream_id(C_ssl) == stream_id)
                    MY_ssl = C_ssl;
                if (SSL_get_stream_id(p_ssl) == stream_id)
                    MY_ssl = p_ssl;
                if (SSL_get_stream_id(r_ssl) == stream_id)
                    MY_ssl = r_ssl;
                if (SSL_get_stream_id(d_ssl) == stream_id)
                    MY_ssl = d_ssl;
                
                int i = jfc_send_stream(MY_ssl, ret, vec);
                
                if (i != 0) {
                    nghttp3_conn_add_write_offset(conn, stream_id, i);
                    printf("MERDE sending %d on %d (%d)\n", ret, stream_id, fin);
                    goto try_again;
                }
            }
            
/*
            if (nghttp3_conn_add_write_offset(conn, stream_id, fin)) {
                printf("nghttp3_conn_add_write_offset failed!\n");
                exit(1);
            }
 */
            printf("SSL_write started!!!\n");
/* JFCLERE
            if (SSL_write(p_ssl, rbuf.begin, nghttp3_buf_len(&rbuf)) != nghttp3_buf_len(&rbuf)) {
                printf("SSL_write failed!!!\n");
                goto err;
            }
 */
            printf("SSL_write Done!!!\n");
            printf("\n");
            printf("\n");
            printf("\n");
            /* calls ossl_quic_conn_stream_conclude(c_ssl) */
/*
            if (!(SSL_stream_conclude(p_ssl, 0))) {
                printf("SSL_stream_conclude failed!!!");
                goto err;
             }
 */

            c_write_done = 1;
            OSSL_sleep(1);
        }

        if (c_write_done && !c_shutdown && c_total_read < sizeof(msg2) - 1) {
            ret = JFC_SSL_read_ex(c_ssl);
            if (ret < 0) {
                printf("\n SSL_read_ex(c_ssl) FAILED!!!");
                goto err;
            } else {
                if (ret > 0) {
                    int i = nghttp3_conn_read_stream(conn, SSL_get_stream_id(c_ssl), msg2, ret, 0);
                    printf("nghttp3_conn_read_stream used %d of %d\n", i, ret);
                }
            }
            ret = JFC_SSL_read_ex(C_ssl);
            if (ret < 0) {
                printf("\n SSL_read_ex(C_ssl) FAILED!!!");
                goto err;
            }
            ret = JFC_SSL_read_ex(p_ssl);
            if (ret < 0) {
                printf("\n SSL_read_ex(p_ssl) FAILED!!!");
                goto err;
            }
            ret = JFC_SSL_read_ex(r_ssl);
            if (ret < 0) {
                printf("\n SSL_read_ex(r_ssl) FAILED!!!");
                goto err;
            }
            ret = JFC_SSL_read_ex(d_ssl);
            if (ret < 0) {
                printf("\n SSL_read_ex(d_ssl) FAILED!!!");
                goto err;
            } else {
                if (ret > 0) {
                    int i = nghttp3_conn_read_stream(conn, SSL_get_stream_id(d_ssl), msg2, ret, 0);
                    printf("nghttp3_conn_read_stream used %d of %d\n", i, ret);
                }
            }
            if (r1_ssl) {
                ret = JFC_SSL_read_ex(r1_ssl);
                if (ret < 0) {
                    printf("\n SSL_read_ex(r1_ssl) FAILED!!!");
                    goto err;
                }
                if (ret > 0) {
                    int i = nghttp3_conn_read_stream(conn, SSL_get_stream_id(r1_ssl), msg2, ret, 0);
                    printf("nghttp3_conn_read_stream used %d of %d\n", i, ret);
                }
            }
            if (r2_ssl) {
                ret = JFC_SSL_read_ex(r2_ssl);
                if (ret < 0) {
                    printf("\n SSL_read_ex(r2_ssl) FAILED!!!");
                    goto err;
                }
                if (ret > 0) {
                    int i = nghttp3_conn_read_stream(conn, SSL_get_stream_id(r2_ssl), msg2, ret, 0);
                    printf("nghttp3_conn_read_stream used %d of %d\n", i, ret);
                }
            }
            if (r3_ssl) {
                ret = JFC_SSL_read_ex(r3_ssl);
                if (ret < 0) {
                    printf("\n SSL_read_ex(r3_ssl) FAILED!!!");
                    goto err;
                }
                if (ret > 0) {
                    int i = nghttp3_conn_read_stream(conn, SSL_get_stream_id(r3_ssl), msg2, ret, 0);
                    printf("nghttp3_conn_read_stream used %d of %d\n", i, ret);
                }
            }
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
        if (C_ssl) {
           /* check the 3 streams we have opened */
           SSL_handle_events(C_ssl);
           SSL_handle_events(p_ssl);
           SSL_handle_events(r_ssl);
           SSL_handle_events(d_ssl);
        }
        SSL_handle_events(c_ssl);
    }

    testresult = 1;
err:
    if (n_ssl)
        SSL_free(n_ssl);
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
