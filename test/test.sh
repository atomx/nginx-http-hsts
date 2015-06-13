#!/bin/sh

$NGINX -p $PWD -c server.conf &
sleep 1

echo http
curl -k -v -H "Host: http.example.com" "http://127.0.0.1:9090" 2>&1 | grep 'Strict-Transport-Security'
echo none
curl -k -v -H "Host: none.example.com" "https://127.0.0.1:9091" 2>&1 | grep 'Strict-Transport-Security'
echo set
curl -k -v -H "Host: set.example.com" "https://127.0.0.1:9091" 2>&1 | grep 'Strict-Transport-Security'
echo subdomains
curl -k -v -H "Host: subdomains.example.com" "https://127.0.0.1:9091" 2>&1 | grep includeSubdomains
echo all
curl -k -v -H "Host: all.example.com" "https://127.0.0.1:9091" 2>&1 | grep includeSubdomains | grep preload

kill `cat test.pid`
sleep 1
