make quic_server_test
unset LD_LIBRARY_PATH
export LD_LIBRARY_PATH=${HOME}/NGHTTP3/lib
./quic_server_test 127.0.0.1 4433 /home/jfclere/CERTS/newcert.pem /home/jfclere/CERTS/newkey.txt.pem
