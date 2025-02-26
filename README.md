
# Installation (this project was conducted on Raspberry Pi 5 (aarch64))

## Set up environment

1. Raspberry Pi 5
   - Environment
     - Raspberry Pi 5 (aarch64)
   - Check the raspberry Pi 5's settings in [[Manual](https://github.com/heeyong-kwon/helper/blob/main/README.md)]

2. Docker and docker compose
   - Check the docker settings in [[Manual](https://github.com/heeyong-kwon/helper/blob/main/README.md)]

3. Clone the repository
```bash
git clone $(git address)
cd socket-network/pqc
(path: $(ROOT_DIR)/pqc/)
docker compose up -d
```

4. If you get the error "no image", build image from Dockerfile
```bash
(path: $(ROOT_DIR)/pqc/)
docker build -t <image_name>
(example) docker build -t mizzou-pqc
docker compose up -d
```


5. (Optional) Test the installation (in the server's docker environment)
```bash
(path: $(ROOT_DIR)/pqc/)
docker exec -it pqc_server bash
    (pqc_server container)
    (path: /)
    cd home/oqs-provider/
    (path: /home/oqs-provider/)
    cd _build && ctest --parallel 5 --rerun-failed --output-on-failure -V
    (Optional) Give a permission to the root directory
    chmod 777 -R ../socket
```












##### Example
1. Generate a digital certificate
```bash
openssl req -x509 -new -newkey falcon1024 -keyout falcon1024_CA.key -out falcon1024_CA.crt -nodes -subj "/CN=test CA" -days 365 -config /usr/local/ssl/openssl.cnf
openssl genpkey -algorithm falcon1024 -out falcon1024_srv.key
openssl req -new -newkey falcon1024 -keyout falcon1024_srv.key -out falcon1024_srv.csr -nodes -subj "/CN=test server" -config /usr/local/ssl/openssl.cnf
openssl x509 -req -in falcon1024_srv.csr -out falcon1024_srv.crt -CA falcon1024_CA.crt -CAkey falcon1024_CA.key -CAcreateserial -days 365
```
2. Run server
```bash
openssl s_server -cert falcon1024_srv.crt -key falcon1024_srv.key -www -tls1_3 -groups mlkem512
```
3. Run client
```bash
openssl s_client -groups mlkem512
```






<!-- 지금 연결은 되는데, verification 21 <- 서버 인증서를 신뢰할 수 없어서 발생하는 문제임. TLS 연결은 성공적으로 설정됨> -->
이거 s_client 실행할 때, "-CAfile falcon1024_CA.crt" 넣어주면, verification code:0 으로 통과 가능


# TODO list:

Exception handling for both server and client sides about identifying not numbered or invalid input data.
   -> Only the server side for now.
   -> Should I add it to the client side as well?


<!-- c code로 실행하는 건 아직 검증 안 됨 -->
This is Hee-Yong's implementation
```bash
(path: /home/socket/pqc/)
cd src
(path: /home/socket/pqc/src/)
mkdir build
cd build
(path: /socket/pqc/src/build)
cmake ..
make
./server
./client
```







<!-- ## How to add submodule
```bash
git submodule add <repositoy.git>
(example)
git submodule add https://github.com/open-quantum-safe/oqs-provider.git
git submodule update --init --recursive
``` -->