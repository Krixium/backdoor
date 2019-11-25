cmake_minimum_required(VERSION 3.0.0)

project(net)

add_library(${PROJECT_NAME} src/authenticator.cpp src/KnockController.cpp src/KnockState.cpp src/NetworkEngine.cpp src/TcpStack.cpp src/UdpStack.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)
