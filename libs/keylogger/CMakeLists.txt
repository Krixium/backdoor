cmake_minimum_required(VERSION 3.0.0)

project(keylogger)

add_library(${PROJECT_NAME} src/Keylogger.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)
