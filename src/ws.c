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

static client *clients[OPEN_MAX]; /* keyword static only for this file */
static int cli_size = 0;

int add_client(client *cli) {
    for (int i = 0; i < OPEN_MAX; i++) {
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
    for (int i = 0; i < OPEN_MAX; i++) {
        if (clients[i] == NULL) continue;
        if (clients[i]->uid == uid) {
            clients[i] = NULL;
            --cli_size;
            DEBUG("remove_client: fd: %d, uid: %llu", i, uid);
            DEBUG("table size now: %d", cli_size);
            break;
        }
    }
}

client *get_client_by_addr(unsigned long long uid) {
    for (int i = 0; i < OPEN_MAX; ++i) {
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

            do_sec_key_sha1(ws_sec_key, &result);
            break;
        }
    }

    char *res;
    res = malloc(MAX_HS_RES_SIZE);
    strcpy(res, HANDSHAKE_RES_HEADER);
    strcat(res, (const char *) result);
    strcat(res, TOKEN_SEP TOKEN_SEP);

    ssize_t wn = write(fd, res, strlen(res));

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
    DEBUG("%s", tmp);
    strcpy(tmp, "");
    free(tmp);
}

void send_to_client(int sender_fd, const unsigned char header[], const unsigned char buf[], unsigned int header_size,
                    unsigned long long size) {
    int i, p;
    unsigned long wc;

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

    for(i = 0; i < OPEN_MAX; i++) {
        if (NULL == clients[i]) continue;
        int fd = clients[i]->fd;

        if (fd == sender_fd) {
            continue;
        }

        wc = write(clients[i]->fd, tmp, buf_size);
        if (wc <= 0) {
            ERROR("errno: %d", errno);
        }
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

    unsigned long next_read_size = MAX_FRAME_SINGLE_BUF_SIZE;

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
            return (-1);
        }
        if (rc == -2) {
            return -2;
        }

        if (df.payload_read_len == (df.payload_final_len + df.header_size)) {
            // Single frame read done
            return (1);
        }

        // Each frame has it's own max size we should control the last buffer size always inner it.
        if (df.payload_read_len + MAX_FRAME_SINGLE_BUF_SIZE > (df.payload_final_len + df.header_size)) {
            next_read_size = (df.payload_final_len + df.header_size) - df.payload_read_len;
        }
    }

    return 0;
}

int read_into_single_buffer(message *msg, struct data_frame *df, unsigned long next_read_size) {
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

    DEBUG("cur_buf_len: %lu, next_read_size: %lu, errno: %d", rn, next_read_size, errno);
    df->payload_read_len+=rn;
    df->cur_buf_len = rn;

    return (1);
}

void reset_data_frame(struct data_frame *df) {

    memset(df->unmasked_data, 0, MAX_FRAME_SINGLE_BUF_SIZE);
    memset(df->mask_key, 0, MASK_KEY_SIZE);
    df->payload_final_len = 0;
    df->header_size = 0;
    df->cur_buf_len = 0;
    df->payload_len = 0;
    df->opcode = 0;
    df->rev1 = 0;
    df->rev2 = 0;
    df->rev3 = 0;
    df->mask_key_index = 0;
    df->fin = 0;
    df->frame_header_handled = 0;
    df->masked = 1;

    df->payload_read_len = 0;
}

int handle_single_buffer(message *msg, struct data_frame *df) {
    int index;
    unsigned long cli_header_size;
    index = 0;
    cli_header_size = 0;
    unsigned char cli_header[10]; /* client header */

handle_other_msg:
    memset(cli_header, 0x0, 10); /* init to zero byte */

    if (df->frame_header_handled == 0) {
        unsigned char cur_byte = df->data[index];
        cli_header[0] = cur_byte; /* the 1st byte */
        // Head buffer of frame
        df->fin = (HEX_0xFF & cur_byte) >> FIN_SHIFT_COUNT;

        msg->is_fragmented = df->fin;

        df->opcode = cur_byte << 1;
        df->opcode = df->opcode >> 1;

        if (df->opcode == OP_CTRL_CLOSE) {
            return -2; /* Client Close */
        }

        if (df->opcode == OP_CTRL_PING) {
            cli_header[0] = cli_header[0] + 0b1;
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
        DEBUG("payload_final_len: %lu", df->payload_final_len);
    }

    // rest sequence buffer of frame
    // unmask data now

    if (index > 0) ++index; // if index > 0 then this will be second time

    int unmask_buffer_index;

    unmask_buffer_index = 0;
    memset(df->unmasked_data, 0, MAX_FRAME_SINGLE_BUF_SIZE);
    unsigned long msg_total_size = cli_header_size + MASK_KEY_SIZE + df->payload_final_len;
    for (; index < df->cur_buf_len; ++index) {
        unsigned char cur_byte = df->data[index];
        df->unmasked_data[unmask_buffer_index++] = cur_byte ^ (df->mask_key[df->mask_key_index]);
        ++df->mask_key_index;
        if (df->mask_key_index == 4) df->mask_key_index = 0;

        // if single message unmasked done and single buf size is greater than single message
        // , we goto handle_other_msg
        if (msg_total_size < df->cur_buf_len && (index + 1) % msg_total_size == 0) {
            // On single buffer unmasked we send it to client
            send_to_client(msg->source_fd, cli_header, df->unmasked_data, cli_header_size,
                           msg_total_size - cli_header_size);

            unsigned long cur_buf_len = df->cur_buf_len;
            reset_data_frame(df);
            df->cur_buf_len = cur_buf_len;

            if (index + 1 == df->cur_buf_len) return 1;
            ++index;
            goto handle_other_msg;
        }
    }

    // On single buffer unmasked we send it to client
    send_to_client(msg->source_fd, cli_header, df->unmasked_data, cli_header_size,
                   msg_total_size - cli_header_size);

    return 1;
}
