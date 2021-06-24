//
// Created by lzjlxebr on 5/24/21.
//

/*

 message: {}
 fragment: []
 buffer: ()

 example:
 m{
    f1[b1(), b2(), b3()],
    f2[b1(), b2(), b3()],
    f3[b1(), b2()]
 }

 m: len: 3072
 f1: len maybe -> 1024, FIN -> 0
 f2: len maybe -> 1024, FIN -> 0
 f3: len maybe -> 1024, FIN -> 1

 */

#include <sys/errno.h>
#include "ws.h"
#include "net_util.h"

static client *clients[MAX_CONN]; /* keyword static only for this file */
static int cli_size = 0;

int add_client(client *cli) {
    for (int i = 0; i < MAX_CONN; i++) {
        if (clients[i] == NULL) {
            clients[i] = cli;
            ++cli_size;
            DEBUG("table size now: %d", cli_size);
            return i;
        }
    }
    return -1;
}

void remove_client(unsigned long long uid) {
    for (int i = 0; i < MAX_CONN; i++) {
        if (clients[i] == NULL) continue;
        if (clients[i]->uid == uid) {
            clients[i] = NULL;
            --cli_size;
            DEBUG("remove_client: %d", i);
            DEBUG("table size now: %d", cli_size);
            break;
        }
    }
}

client *get_client_by_addr(unsigned long long uid) {
    for (int i = 0; i < MAX_CONN; ++i) {
        client *cli = clients[i];

        if (cli == NULL) continue;
        if (cli->uid == uid) return cli;
    }
    return NULL;
}

int handle_handshake_opening(int fd) {
    ssize_t n;
    char req[MAX_HS_REQ_SIZE];
    n = read(fd, &req, sizeof(req));
    if (n < 0) {
        DEBUG("read error: %zd", n);
        return (-1);
    }

    if (n == 0) {
        DEBUG("read size: %d", 0);
        return (-1);
    }

    req[n] = '\0';
    char *last;

    char *ws_sec_key = NULL;
    unsigned char *result;

    for (char *token = strtok_r(req, TOKEN_SEP, &last); token ; token = strtok_r(NULL, TOKEN_SEP, &last)) {
        if (strstr(token, WS_SEC_KEY)) {
            ws_sec_key = strtok(token, ": ");
            ws_sec_key = strtok(NULL, ": ");

            DEBUG("We got sec-wb-key: %s", ws_sec_key);
            do_sec_key_sha1(ws_sec_key, &result);
            DEBUG("SHA1 result: %s", result);
            break;
        }
    }

    char *res;
    res = malloc(MAX_HS_RES_SIZE);
    strcpy(res, HANDSHAKE_RES_HEADER);
    strcat(res, (const char *) result);
    strcat(res, TOKEN_SEP TOKEN_SEP);

    ssize_t wn = write(fd, res, strlen(res));
    DEBUG("response(size: %zd): %s", wn, res);

    free(res);

    return 0;
}

void do_sec_key_sha1(char *key, unsigned char **result) {
    unsigned char hash[SHA1HashSize];
    SHA1Context ctx;
    char *_key;

    _key = malloc(sizeof(char) * CAT_KEY_LEN);

    // concat key with GUID
    strcpy(_key, key);
    strcat(_key, GUID);

    // sha1
    SHA1Reset(&ctx);
    SHA1Input(&ctx, (const uint8_t *)_key, CAT_KEY_LEN);
    SHA1Result(&ctx, hash);

    // base64 encode
    *result = base64_encode(hash, SHA1HashSize, NULL);
    *(*result + strlen((const char*) *result) - 1) = '\0';

    free(_key);
}

void dump_data_frame(struct data_frame *df) {
    unsigned char *rbuff = df->data;
    int nlc = 0;
    char *tmp;
    tmp = malloc(144);
    for (int i = 0; i < MAX_FRAME_SINGLE_BUF_SIZE; ++i) {
        if (nlc == 16) {
            nlc = 0;
            DEBUG("%s", tmp);
            strcpy(tmp, "");
        }
        strcat(tmp, wrap_char2str(rbuff[i]));
        strcat(tmp, " ");

        ++nlc;
    }
    strcpy(tmp, "");
    free(tmp);
}

void dump_data_buf(const unsigned char buf[], unsigned long long size) {
    int nlc = 0;
    unsigned long long max = 16;
    if (size < max) max = size - 1;
    char *tmp;
    tmp = malloc(144);
    for (int i = 0; i < size; ++i) {
        if (nlc == max) {
            nlc = 0;
            DEBUG("%s", tmp);
            strcpy(tmp, "");
        }
        strcat(tmp, wrap_char2str(buf[i]));
        strcat(tmp, " ");

        ++nlc;
    }
    strcpy(tmp, "");
    free(tmp);
}

void send_to_client(int sender_fd, const unsigned char header[], const unsigned char buf[], unsigned int header_size,
                    unsigned long long size) {
    int i, p;

    /* trim buf */
    for(p = 0; p < size; p++) {
        unsigned char ch = buf[p];
        if (ch == '\0') break;
    }
    size = p;

    unsigned long long buf_size = header_size + size;
    unsigned char tmp[buf_size];
    memset(tmp, 0x0, buf_size);

    for(i = 0; i < header_size; i++) {
        tmp[i] = header[i];
    }

    for(p = 0; p < size; p++) {
        unsigned char ch = buf[p];
        if (ch == '\0') break;
        tmp[i] = buf[p];
        i++;
    }

    DEBUG("cli_size: %d", cli_size);
    for(i = 0; i < cli_size; i++) {
        int fd = clients[i]->fd;

        if (fd == sender_fd) {
            continue;
        }

        DEBUG("ready send to client: %d", fd);
        write(clients[i]->fd, tmp, sizeof(tmp));
    }


}

int handle_conn(int conn_fd) {
    int rc;
    message *msg;
    msg = malloc(sizeof(message));
    msg->source_fd = conn_fd;
    msg->is_fragmented = 0;

    DEBUG("START HANDLE CONN... fd: %d", conn_fd);
    struct data_frame df;
    memset(&df, 0, sizeof(df));

    unsigned long long next_read_size = MAX_FRAME_SINGLE_BUF_SIZE;

    while (1) {
        // Read until meet max length
        int rib = read_into_single_buffer(msg, &df, next_read_size);
        if (rib == -1) {
            ERROR("read_into_single_buffer failed: -1");
            return (-1);
        }


        if (df.cur_buf_len == 0) {
            break;
        }

        rc = handle_single_buffer(msg, &df);
        if (rc == -1) {
            ERROR("handle_single_buffer failed -1");
            DEBUG("(-1)PAYLOAD size (in byte): %llu",  df.payload_read_len);
            return (-1);
        }
        if (rc == -2) {
            DEBUG("(-2)PAYLOAD size (in byte): %llu",  df.payload_read_len);
            return -2;
        }

        if (df.payload_read_len == (df.payload_final_len + df.header_size)) {
            // Single frame read done
            DEBUG("(1)PAYLOAD size (in byte): %llu",  df.payload_read_len);
//            send_to_client(msg->source_fd);
            return (1);
        }

        // Each frame has it's own max size we should control the last buffer size always inner it.
        if (df.payload_read_len + MAX_FRAME_SINGLE_BUF_SIZE > (df.payload_final_len + df.header_size)) {
            next_read_size = (df.payload_final_len + df.header_size) - df.payload_read_len;
        }
    }

    return 0;
}

int read_into_single_buffer(message *msg, struct data_frame *df, unsigned long long next_read_size) {
repeat:
    memset(df->data, 0, MAX_FRAME_SINGLE_BUF_SIZE);
    ssize_t rn = read(msg->source_fd, df->data, next_read_size);
    df->cur_buf_len = 0;

    if (rn < 0) {
        if (errno == ECONNRESET) return -1; /* connection reset by client */
        if (errno == EAGAIN) goto repeat;
        ERROR("read_into_single_buffer error: %zd", rn);
        return (-1);
    }
    if (rn == 0) return 0;

    df->payload_read_len+=rn;
    df->cur_buf_len = rn;

//    dump_data_frame(df);

    return (1);
}

int handle_single_buffer(message *msg, struct data_frame *df) {
    int index, cli_index, cli_header_size;

    index = 0;
    cli_index = 0;

    unsigned char cli_header[10]; /* client header */
    memset(cli_header, 0x0, 10); /* init to zero byte */
    unsigned char cli_df[MAX_FRAME_SINGLE_BUF_SIZE];

    if (df->frame_header_handled == 0) {
        unsigned char cur_byte = df->data[index];
        cli_header[0] = cur_byte; /* the 1st byte */
        // Head buffer of frame
        df->fin = (HEX_0xFF & cur_byte) >> FIN_SHIFT_COUNT;

        msg->is_fragmented = df->fin;

        df->opcode = cur_byte << 1;
        df->opcode = df->opcode >> 1;
        DEBUG("FIN: %d, opcode: %s", df->fin, wrap_char2str(df->opcode));

        if (df->opcode == OP_CTRL_CLOSE) {
            return -2; /* Client Close */
        }

        cur_byte = df->data[++index];
        cli_header[1] = cur_byte; /* the 2nd byte */
        /* https://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit */
        cli_header[1] &= ~(1UL << 7); /* we clear MASK bit */
        // MASK
        df->masked = (HEX_0xFF & cur_byte) >> MASK_SHIFT_COUNT;

        // Payload len byte
        df->payload_len = cur_byte << 1;
        df->payload_len = df->payload_len >> 1;

        if (df->payload_len == PL_LEN_VAL_127) {
            // Path 3: Payload len == 127 ext payload len 64 mask start at byte 10
            // combine 8 bytes into final length
            cur_byte = df->data[++index];
            df->payload_final_len = cur_byte;
            df->payload_final_len = df->payload_final_len << 8;
            cli_header[2] = cur_byte;

            for (int i = 0; i < 6; ++i) {
                cur_byte = df->data[++index];
                df->payload_final_len += cur_byte;
                df->payload_final_len = df->payload_final_len << 8;

                cli_header[3 + i] = cur_byte;
            }

            cur_byte = df->data[++index];
            cli_header[9] = cur_byte;
            df->payload_final_len += cur_byte;
            df->header_size = 14;

            cli_header_size = 10;
        } else if (df->payload_len == PL_LEN_VAL_126) {
            // Path 2: Payload len == 126 ext payload len 16 mask start at byte 4
            // combine 8 bytes into final length
            cur_byte = df->data[++index];
            df->payload_final_len = cur_byte;
            df->payload_final_len = df->payload_final_len << 8;
            cli_header[2] = cur_byte;

            cur_byte = df->data[++index];
            cli_header[3] = cur_byte;
            df->payload_final_len += cur_byte;
            df->header_size = 8;

            cli_header_size = 4;
        } else {
            // Path 1: Payload len < 126 mask start at byte 2
            df->payload_final_len = df->payload_len;
            df->header_size = 6;

            cli_header_size = 2;
        }

        // Masking-key (Extended payload length is 16 or 64)
        int i = 0;
        do {
            cur_byte = df->data[++index];
            df->mask_key[i] = cur_byte;
        } while (++i < 4);

        df->frame_header_handled = 1;
        DEBUG("payload_final_len: %llu", df->payload_final_len);
    }

    // rest sequence buffer of frame
    // unmask data now

    if (index > 0) ++index; // if index > 0 then this will be second time

    int i;
    for (i = index; i < df->cur_buf_len; ++i) {
        unsigned char cur_byte = df->data[i];

        if (df->unmask_buffer_index == MAX_UNMASK_BUF_SIZE) {
            df->unmask_buffer_index = 0;
        }
        unsigned char cb = cur_byte ^ (df->mask_key[df->mask_key_index]);
        cli_df[cli_index] = cb;
        ++cli_index;

        df->unmasked_payload[df->unmask_buffer_index++] = cb;
        ++df->mask_key_index;
        if (df->mask_key_index == 4) df->mask_key_index = 0;
    }

    // On single buffer unmasked we send it to client
    send_to_client(msg->source_fd, cli_header, cli_df, cli_header_size, df->cur_buf_len - cli_header_size);

    return 1;
}
