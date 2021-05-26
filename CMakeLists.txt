cmake_minimum_required(VERSION 3.19)
project(websocket_server C)

set(CMAKE_C_STANDARD 11)

add_executable(websocket_server ./src/main.c ./src/handshake.h ./src/ws.h
        ./src/ws.c
        ./src/sha1.h
        ./src/sha1.c
        ./src/base64.c
        ./src/base64.h
        src/net_util.h src/net_util.c src/base.h)