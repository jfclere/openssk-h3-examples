quic_client_test: quic_client_test.c
	cc     quic_client_test.c   -o quic_client_test -I${HOME}/OPENSSL/include -I${HOME}/NGHTTP3/include -L ${HOME}/OPENSSL/lib64/ -L ${HOME}/NGHTTP3/lib -lcrypto -lssl -lapr-1 -l nghttp3
quic-client-block: quic-client-block.c
	cc     quic-client-block.c   -o quic-client-block -I${HOME}/OPENSSL/include -L ${HOME}/OPENSSL/lib64/ -lcrypto -lssl
