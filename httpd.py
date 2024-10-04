#!/usr/bin/env python3
"""
License: MIT License
Copyright (c) 2023 Miel Donkers

Very simple HTTPS server in python for logging requests
Usage::
    ./server.py <port> <keyfile> <certfile>
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import ssl
import socket

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-length', '22')
        self.send_header('alt-svc', 'h3=":4433"; ma=60; h3=":4433"; persist=1')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write(b"reload to get HTTP/3\n\r")
        self.connection.close()
        logging.info("End of request\n")

def run(port=4433, keyfile="privkey.pem", certfile="pubcert.pem"):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd =  ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.server_side=True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 4:
        run(port=int(argv[1], keyfile=argv[2], certfile=argv[3]))
    else:
        run()
