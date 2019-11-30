cmake_minimum_required(VERSION 3.0.0)

project(rce)

add_library(${PROJECT_NAME} src/RemoteCodeExecuter.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include ../net/include)
