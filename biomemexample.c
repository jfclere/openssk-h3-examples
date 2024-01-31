#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

void init_OpenSSL()
{
	if(!SSL_library_init())
	{
		printf("OpenSSL initialization failed!\n");
		exit(1);
	}
	SSL_load_error_strings();
}

int client(int fdread, int fdwrite)
{
	BIO *client_r = BIO_new(BIO_s_mem());
	BIO *client_w = BIO_new(BIO_s_mem());

	SSL *ssl_client;
	SSL_CTX *ctx_client;

	init_OpenSSL();

	ctx_client = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_verify(ctx_client, SSL_VERIFY_NONE, NULL);
	ssl_client = SSL_new(ctx_client);

	SSL_set_bio(ssl_client, client_r, client_w);
	SSL_set_connect_state(ssl_client);

	bool fin_client = false;
	char buf[4096];
	int n;
        int error = SSL_ERROR_NONE;
	while(!fin_client)
	{
		fflush(stdout);
                if (!SSL_is_init_finished(ssl_client)) {
                  printf("client: SSL_do_handshake\n");
		  fflush(stdout);
		  int ret = SSL_do_handshake(ssl_client);
                  error =  SSL_get_error(ssl_client, ret);
                  printf("client: SSL_do_handshake %d\n", error);
		  fflush(stdout);
                }
                fd_set fdset;
                struct timeval tv;
                FD_ZERO(&fdset);
                FD_SET(fdread, &fdset);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                int err = select(fdread+1, &fdset, NULL, NULL, &tv);
                if (err > 0) {
                  n = read(fdread, buf, 4096);
                  if (n <=0)
                    break;
	          int ret = BIO_write(client_r, buf, n);
                  error = SSL_get_error(ssl_client, ret);
                  printf("client  received %d return %d\n", n, ret);
                }
		fflush(stdout);
                if (error == SSL_ERROR_WANT_READ) {
                  printf("client: SSL_ERROR_WANT_READ\n");
		  fflush(stdout);
		  int ret = BIO_read(client_w, buf, 4096);
                  if (ret>0) {
                    write(fdwrite, buf, ret);
                    printf("client SSL_ERROR_WANT_READ writen %d\n", ret);
                    fflush(stdout);
                  }  else  {
                    error =  SSL_get_error(ssl_client, ret);
                    printf("client SSL_ERROR_WANT_READ error %d\n", error);
                    fflush(stdout);
                  }
                  continue;
                }
                if (error == SSL_ERROR_WANT_WRITE) {
                  printf("client SSL_ERROR_WANT_WRITE\n");
		  fflush(stdout);
                  n = read(fdread, buf, 4096);
                  if (n<=0) {
                    printf("read failed %d", errno);
                    break;
                  }
	          int ret = BIO_write(client_r, buf, n);
                  error =  SSL_get_error(ssl_client, ret);
                  printf("client SSL_ERROR_WANT_WRITE writen %d\n", ret);
		  fflush(stdout);
                  continue;
                
                }
                printf("client: OOPS! %d\n", error);
                fin_client = SSL_is_init_finished(ssl_client);
        }
        printf("client done! %d\n", SSL_is_init_finished(ssl_client));
        sleep(5);
}
int server(int fdread, int fdwrite)
{
	BIO *srv_r  = BIO_new(BIO_s_mem());
	BIO *srv_w = BIO_new(BIO_s_mem());
	
	SSL *ssl_srv;
	SSL_CTX *ctx_srv;

	init_OpenSSL();

	ctx_srv = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_verify(ctx_srv, SSL_VERIFY_NONE, NULL);
        /* set key / cert */
        SSL_CTX_use_certificate_file(ctx_srv, "/home/jfclere/CERTS/newcert.pem", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx_srv, "/home/jfclere/CERTS/newkey.txt.pem", SSL_FILETYPE_PEM);
	ssl_srv = SSL_new(ctx_srv);

	SSL_set_bio(ssl_srv, srv_r, srv_w);
	SSL_set_accept_state(ssl_srv);

	bool fin_srv = false;
	char buf[4096];
	int n;
        int error = SSL_ERROR_NONE;
	while(!fin_srv)
	{
                if (!SSL_is_init_finished(ssl_srv)) {
                  printf("server  SSL_do_handshake\n");
		  fflush(stdout);
		  int ret = SSL_do_handshake(ssl_srv);
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server: SSL_do_handshake %d\n", error);
		  fflush(stdout);
                }
                fd_set fdset;
                struct timeval tv;
                FD_ZERO(&fdset);
                FD_SET(fdread, &fdset);
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                int err = select(fdread+1, &fdset, NULL, NULL, &tv);
                if (err > 0) {
                  n = read(fdread, buf, 4096);
                  if (n <=0) {
                    printf("server received read error\n");
                    break;
                  }
	          int ret = BIO_write(srv_r, buf, n);
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server received %d return %d\n", n, ret);
                } else {
                  printf("server select %d error???\n", err);
                }
		fflush(stdout);
                if (error == SSL_ERROR_SSL) {
                    printf("server SSL_ERROR_SSL error\n");
		    fflush(stdout);
                    break;
                }
                if (error ==  SSL_ERROR_WANT_READ) {
                  printf("server SSL_ERROR_WANT_READ\n");
		  fflush(stdout);
		  n = BIO_read(srv_w, buf, 4096);
                  if (n<0) {
                    printf("server SSL_SSL_ERROR_WANT_READ error %d\n", SSL_get_error(ssl_srv, n));
	            fflush(stdout);
                    error = SSL_get_error(ssl_srv, n);
                  } else {
                    write(fdwrite, buf, n);
                    printf("server SSL_ERROR_WANT_READ writen %d\n", n);
		    fflush(stdout);
                  }
		  fflush(stdout);
                  continue;
                }
                if (error == SSL_ERROR_WANT_WRITE) {
                  printf("server SSL_ERROR_WANT_WRITE\n");
		  fflush(stdout);
                  n = read(fdread, buf, 4096);
                  if (n<=0) {
                    printf("failed %d\n", errno);
		    fflush(stdout);
                    break;
                  }
		  int ret = BIO_write(srv_r, buf, n);
                  error = SSL_get_error(ssl_srv, ret);
                  printf("server  SSL_ERROR_WANT_WRITE %d return %d\n", n, ret);
	          fflush(stdout);
                  continue;
                }
                printf("server: OOPS! %d\n", error);
                fin_srv = SSL_is_init_finished(ssl_srv);
		
	}
        printf("server done! %d\n", SSL_is_init_finished(ssl_srv));

	return 0;
}
int main()
{
       int     fd[2], df[2];
       pid_t   childpid;

       if (pipe(fd)==-1) {
               perror("pipe");
               exit(1);
       }
       if (pipe(df)==-1) {
               perror("pipe");
               exit(1);
       }
       
       if((childpid = fork()) == -1)
       {
               perror("fork");
               exit(1);
       }
       if (childpid == 0) {
         close(fd[1]);
         close(df[0]);
         client(fd[0], df[1]);
       } else {
         close(fd[0]);
         close(df[1]);
         server(df[0], fd[1]);
       }
       printf("exited!");
}
