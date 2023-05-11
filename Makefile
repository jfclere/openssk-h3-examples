quic_client_test: quic_client_test.c
	cc     quic_client_test.c   -o quic_client_test -I${HOME}/OPENSSL/include -L ${HOME}/OPENSSL/lib64/ -lcrypto -lssl -lapr-1
