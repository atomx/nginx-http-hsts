#!/bin/sh

openssl req -nodes -newkey rsa:2048 -keyout server.key -sha256 -out server.csr -subj "/C=MY/ST=WP Kuala Lumpur/L=Kuala Lumpur/O=Test/CN=*.example.com"
openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
