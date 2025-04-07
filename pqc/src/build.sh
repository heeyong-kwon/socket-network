#!/bin/bash

mkdir build
cd build
cmake ..
make

ALG="falcon1024"
openssl req -x509 -new -newkey ${ALG} -keyout ${ALG}_CA.key -out ${ALG}_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
openssl genpkey -algorithm ${ALG} -out ${ALG}_srv.key
openssl req -new -newkey ${ALG} -keyout ${ALG}_srv.key -out ${ALG}_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
openssl x509 -req -in ${ALG}_srv.csr -out ${ALG}_srv.crt -CA ${ALG}_CA.crt -CAkey ${ALG}_CA.key -CAcreateserial -days 365
