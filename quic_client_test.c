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


static const char msg1[] = "GET LICENSE.txt\r\n";
static char msg2[16000];

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

    c_net_bio = c_net_bio_own = BIO_new_dgram(c_fd, 0);
    if (c_net_bio == NULL)
        goto err;

    if (!BIO_dgram_set_peer(c_net_bio, s_addr_))
        goto err;

    c_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (c_ctx == NULL)
        goto err;

    c_ssl = SSL_new(c_ctx);
    if (c_ssl == NULL)
        goto err;

    SSL_set_tlsext_host_name(c_ssl, hostname); /* JFC add */

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

    for (;;) {
        if (apr_time_now() - start_time >= 30000) {
            TEST_error("timeout while attempting QUIC client test\n");
            goto err;
        }

        if (!c_connected) {
            ret = SSL_connect(c_ssl);
            printf("SSL_connect returns %d %d\n", ret, is_want(c_ssl, ret));
            if (!(ret == 1 || is_want(c_ssl, ret))) {
                TEST_error("SSL_connect failed!\n");
                goto err;
            }

            if (ret == 1) {
                c_connected = 1;
                TEST_info("Connected!");
            }
        }

        if (c_connected && !c_write_done) {
            if (SSL_write(c_ssl, msg1, sizeof(msg1) - 1) !=
                             (int)sizeof(msg1) - 1)
                goto err;

            if (!(SSL_stream_conclude(c_ssl, 0)))
                goto err;

            c_write_done = 1;
        }

        if (c_write_done && !c_shutdown && c_total_read < sizeof(msg2) - 1) {
            ret = SSL_read_ex(c_ssl, msg2 + c_total_read,
                              sizeof(msg2) - 1 - c_total_read, &l);
            if (ret != 1) {
                if (SSL_get_error(c_ssl, ret) == SSL_ERROR_ZERO_RETURN) {
                    c_shutdown = 1;
                    TEST_info("Message: \n%s\n", msg2);
                } else if (!(is_want(c_ssl, ret))) {
                    goto err;
                }
            } else {
                c_total_read += l;

                if (c_total_read != sizeof(msg2) - 1)
                    goto err;
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
        OSSL_sleep(0);
        SSL_tick(c_ssl);
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
        printf("port:i %s invalid\n", argv[2]);
        exit(1);
    }
    if (!test_quic_client(argv[1], port))
        printf("failed!!!");
    return 1;
}
