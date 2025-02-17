cmake_minimum_required(VERSION 3.10)
project(PQC_TLS)

set(CMAKE_C_STANDARD 11)

# OpenSSL 라이브러리 경로 설정
# Set the OpenSSL library path
find_package(OpenSSL REQUIRED)

# 서버 빌드 설정
# Set the server build
add_executable(server pq_tls_server.c)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)

# 클라이언트 빌드 설정
# Set the client build
add_executable(client pq_tls_client.c)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)
