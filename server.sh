make server
export LD_LIBRARY_PATH=/home/jfclere/openssl:${HOME}/NGHTTP3/lib
./server 4433 pubcert.pem privkey.pem
