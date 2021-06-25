//
// Created by lzjlxebr on 5/23/21.
// https://datatracker.ietf.org/doc/rfc6455/
//

#ifndef WEBSOCKET_SERVER_WS_H
#define WEBSOCKET_SERVER_WS_H

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "base64.h"
#include "sha1.h"
#include "handshake.h"
#include "base.h"

#define MAX_CONN 10

// Single frame can be split into sort of buffers
// this macro is max size of single buffer in byte
#define MAX_FRAME_SINGLE_BUF_SIZE       4196

// Data after unmasked buffer size
#define MAX_UNMASK_BUF_SIZE       81920

// Frame size to client
#define CLI_FRAME_SIZE 2048


// Max queue size of listen()
#define	MAX_LISTEN_Q		1024

// Max size of handshake request message size in byte
#define	MAX_HS_REQ_SIZE		1024

// Max size of handshake response message size in byte
#define MAX_HS_RES_SIZE     180

// FIN of data frame shift count
// |<- this is FIN bit
// 10000000
// 10000000 >> 7 = 00000001
// then we get FIN bit
#define FIN_SHIFT_COUNT 7

// MASK of data frame shift count
// |<- this is MASK bit
// 10000000
// 10000000 >> 7 = 00000001
// then we get MASK bit
#define MASK_SHIFT_COUNT 7

// Payload length value 127
#define PL_LEN_VAL_127 127

// Payload length value 126
#define PL_LEN_VAL_126 126

// Just 0xFF
#define HEX_0xFF 0xFF

// Header separator
#define TOKEN_SEP "\r\n"

// Constant Sec-WebSocket-Key
#define WS_SEC_KEY "Sec-WebSocket-Key"

// Constant GUID
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// SHA1 stuff
#define CAT_KEY_LEN 60

#define OP_CTRL_CLOSE 0x8

/* Mask key size is always 4 */
#define MASK_KEY_SIZE 4



typedef struct message_t {
    // From source
    int source_fd;
    // To target
    int target_fd;
    unsigned char type;
    // message
    unsigned char is_fragmented;
} message;

typedef struct client_t {
    struct sockaddr_in cli_addr;

    unsigned long long uid; /* Unique to each connection */

    char is_shaken;

    int fd;

    unsigned char status; /* TODO */
} client;

// Table for connections
int add_client(client*);
client *get_client_by_addr(unsigned long long uid);
void remove_client(unsigned long long uid);

struct data_frame {
    // masked frame data
    unsigned char data[MAX_FRAME_SINGLE_BUF_SIZE];

    // Unmasked frame data
    unsigned char unmasked_data[MAX_FRAME_SINGLE_BUF_SIZE];

    // bit [1] len=1
    unsigned char fin;

    // bit [4, 7] len=4
    unsigned char opcode;
    unsigned char rev1;
    unsigned char rev2;
    unsigned char rev3;

    // bit [8] len=1
    unsigned char masked;

    // header length in bytes
    unsigned char header_size;
    // bit [9, 15] len=7
    unsigned char payload_len;

    // final length of payload, NOT message total length
    unsigned long payload_final_len;

    // Current payload read length
    unsigned long long payload_read_len;

    // Current buffer length (haw many bytes read from source fd)
    unsigned long cur_buf_len;

    // If header of frame handled
    unsigned char frame_header_handled;

    // Cycle: 0 -> 1 -> 2 -> 3 -> 0
    unsigned char mask_key_index;

    // if len of ext_payload_len = 16 then bit [32，63]
    // else bit [80, 111]
    // length is 32-bit
    unsigned char mask_key[MASK_KEY_SIZE];
};

typedef struct data_frame_cli_header {
    // bit [1] len=1
    unsigned char fin;

    // bit [4, 7] len=4
    unsigned char opcode;
    unsigned char rev1;
    unsigned char rev2;
    unsigned char rev3;
} data_frame_cli_header;

// Hand shake
int handle_handshake_opening(int fd);
void do_sec_key_sha1(char *key, unsigned char **result);


int read_into_single_buffer(message *msg, struct data_frame *df, unsigned long next_read_size);

// Receiving message
int handle_conn(int conn_fd);

/*
 * Handle single buffer.
 * After we modify io model to non-blocking, single buffer MAY contains two or more messages
 * so we should handle message one by one from this single buffer.
 * IT'S SO FUCKLLY.
 */
int handle_single_buffer(message *msg, struct data_frame *df);

/*
 * Method of handle single buffer one by one
 * EXCEPT DATA
 */
void reset_data_frame(struct data_frame *df);

/*
 * Sending message to client.
 * Every time when server received a buffer of data
 * this routine will be called.
 *
 * sender_fd indicates which one is sender
 */
void send_to_client(int sender_fd, const unsigned char header[], const  unsigned char buf[], unsigned int header_size,
                    unsigned long long size);

// Debug
void dump_data_buf(const unsigned char buf[], unsigned long long size);
void dump_data_frame(struct data_frame *df);

#endif //WEBSOCKET_SERVER_WS_H
