cmake_minimum_required(VERSION 3.0.0)

project(filemon)

add_library(${PROJECT_NAME} src/FileMonitor.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)
