//
// Created by lzjlxebr on 5/23/21.
// https://datatracker.ietf.org/doc/rfc6455/
//

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "sha1.h"
#include "handshake.h"

#ifndef WEBSOCKET_SERVER_WS_H
#define WEBSOCKET_SERVER_WS_H

#define	MAX_LISTEN_Q		1024
#define	MAX_HEADER_LEN		2048
#define MAX_HS_RES_LEN      180

#define WS_SEC_KEY "Sec-WebSocket-Key"
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define CAT_KEY_LEN 60

struct data_frame {};
struct message {};

void handle_handshake_opening(int);
void do_sec_key_sha1(char *key, unsigned char **result);

//void check_handshake_header();
//void handshake_accept(int, size_t);
//
//void on_receive_message();
//void send_message();
//
//void handle_handshake_closing();


#endif //WEBSOCKET_SERVER_WS_H
