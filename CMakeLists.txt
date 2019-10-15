cmake_minimum_required(VERSION 3.0.0)
project(backdoor VERSION 0.1.0)

include(CTest)
enable_testing()

include(FindPCAP.cmake)

add_executable(backdoor main.c)
target_link_libraries(backdoor ${PCAP_LIBRARY})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
