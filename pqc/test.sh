#!/bin/bash

bash add_new.sh

openssl req -x509 -new -newkey kbl_p256_falcon512 -keyout kbl_p256_falcon512_CA.key -out kbl_p256_falcon512_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
openssl genpkey -algorithm kbl_p256_falcon512 -out kbl_p256_falcon512_srv.key
openssl req -new -newkey kbl_p256_falcon512 -keyout kbl_p256_falcon512_srv.key -out kbl_p256_falcon512_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
openssl x509 -req -in kbl_p256_falcon512_srv.csr -out kbl_p256_falcon512_srv.crt -CA kbl_p256_falcon512_CA.crt -CAkey kbl_p256_falcon512_CA.key -CAcreateserial -days 365

# rm kbl_p256_falcon512_*

