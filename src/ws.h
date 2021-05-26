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
#include "base.h"

#ifndef WEBSOCKET_SERVER_WS_H
#define WEBSOCKET_SERVER_WS_H



#define MAX_FRAME_LEN       512
#define	MAX_LISTEN_Q		1024
#define	MAX_HEADER_LEN		2048
#define MAX_HS_RES_LEN      180

#define FIN_SHIFT_COUNT 7
#define MASK_SHIFT_COUNT 7

#define PL_LEN_127 127
#define PL_LEN_126 126

#define EXT_PL_BITS_16 16
#define EXT_PL_BITS_64 64



#define HEX_0xFF 0xFF

#define BYTE_IDX_FIN 0
#define BYTE_IDX_MASK 1
#define BYTE_IDX_ETX_PL_LEN 2

#define BYTE_MASK_KEY_EXT_16 4
#define BYTE_MASK_KEY_EXT_64 10

#define BYTE_PL_DATA_EXT_16 8
#define BYTE_PL_DATA_EXT_64 14

#define OPC_POS 4
#define MASK_POS 8

#define OPC_CONTINUE 0x0
#define OPC_TYPE_TEXT 0x1
#define OPC_TYPE_BIN 0x2
#define OPC_CONN_CLS 0x8
#define OPC_PING 0x9
#define OPC_PONG 0xA
#define OPC_CONN_CLS 0x8



#define WS_SEC_KEY "Sec-WebSocket-Key"
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define CAT_KEY_LEN 60

struct data_frame {
    // frame data
    unsigned char data[MAX_FRAME_LEN];

    // current byte
    unsigned char *cur_byte;

    // current byte count
    unsigned int cur_b_index;

    // bit [1] len=1
    unsigned char fin;

    // bit [4, 7] len=4
    unsigned char opcode;

    unsigned char rev1;
    unsigned char rev2;
    unsigned char rev3;

    // bit [8] len=1
    unsigned char masked;

    // bit [9, 15] len=7
    unsigned char payload_len;

    // final length of payload
    unsigned long long payload_final_len;

    // Extended payload length in bit
    unsigned char ext_payload_bits;

    // Extended payload length, max size 64-bit
    // if payload_len = 127 then 64 (bit [16, 79])
    // else 16 (bit [16, 31])
    unsigned long long ext_payload_len;

    // if len of ext_payload_len = 16 then bit [32，63]
    // else bit [80, 111]
    // length is 32-bit
    unsigned char mask_key[4];

    // Read count for payload data bytes reading
    unsigned int r_count;

    // Unmasked payload data buffer
    unsigned char unmasked_payload[1024];
};
struct message {};

void print_bin_char_pad(unsigned char c);

int handle_handshake_opening(int);
void do_sec_key_sha1(char *key, unsigned char **result);

int read_frame(int fd, struct data_frame *df);
void read_byte_from_frame_by_offset(struct data_frame *df, unsigned char offset);

void handle_data_frame(int fd);



//void check_handshake_header();
//void handshake_accept(int, size_t);
//
//void on_receive_message();
//void send_message();
//
//void handle_handshake_closing();


#endif //WEBSOCKET_SERVER_WS_H
