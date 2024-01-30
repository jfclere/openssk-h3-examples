#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <stdbool.h>

void init_OpenSSL()
{
	if(!SSL_library_init())
	{
		printf("OpenSSL initialization failed!\n");
		exit(1);
	}
	SSL_load_error_strings();
}

int main()
{
	BIO *client_r = BIO_new(BIO_s_mem());
	BIO *client_w = BIO_new(BIO_s_mem());
	BIO *srv_r  = BIO_new(BIO_s_mem());
	BIO *srv_w = BIO_new(BIO_s_mem());
	
	SSL *ssl_client, *ssl_srv;
	SSL_CTX *ctx_client, *ctx_srv;

	init_OpenSSL();

	ctx_client = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_verify(ctx_client, SSL_VERIFY_NONE, NULL);
	ssl_client = SSL_new(ctx_client);
	SSL_set_connect_state(ssl_client);

	ctx_srv = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_verify(ctx_srv, SSL_VERIFY_NONE, NULL);
	ssl_srv = SSL_new(ctx_srv);
	SSL_set_accept_state(ssl_srv);

	SSL_set_bio(ssl_client, client_r, client_w);
	SSL_set_bio(ssl_srv, srv_r, srv_w);

	bool fin_client = false, fin_srv = false;
	char buf[4096];
	int n;
	while(!fin_client && !fin_srv)
	{
		if(!(fin_client = SSL_is_init_finished(ssl_client)))
		{
			SSL_do_handshake(ssl_client);
			n = BIO_read(client_w, buf, 4096);
			BIO_write(srv_r, buf, n);
                        printf("c");
		}

		if(!(fin_srv = SSL_is_init_finished(ssl_srv)))
		{
			SSL_do_handshake(ssl_srv);
			n = BIO_read(srv_w, buf, 4096);
			BIO_write(client_r, buf, n);
                        printf("s");
		}
	}

	return 0;
}
