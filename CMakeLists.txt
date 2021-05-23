cmake_minimum_required(VERSION 3.19)
project(websocket_server C)

set(CMAKE_C_STANDARD 11)

add_executable(websocket_server main.c handshake.h)