cmake_minimum_required(VERSION 3.10)

# OpenSSL 라이브러리 찾기
find_package(OpenSSL REQUIRED)

# 실행 파일 생성
add_executable(cert_test cert_test.c cert_test_funcs.c)
# add_executable(cert_test cert_test.c cert_test_funcs.c cert_test_params.h)

# OpenSSL 라이브러리 링크
target_link_libraries(cert_test OpenSSL::SSL OpenSSL::Crypto)
