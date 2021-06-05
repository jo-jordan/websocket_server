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

#include "ws.h"
#include "net_util.h"

int handle_handshake_opening(message *msg) {
    ssize_t n;
    char req[MAX_HS_REQ_SIZE];
    n = read(msg->source_fd, &req, sizeof(req));
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

    ssize_t wn = write(msg->source_fd, res, strlen(res));
    DEBUG("response(size: %zd): %s", wn, res);

    free(res);

    msg->is_handshake = 1;
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
    tmp = malloc(32);
    for (int i = 0; i < MAX_FRAME_SINGLE_BUF_SIZE; ++i) {
        if (nlc == 16) {
            nlc = -1;
            DEBUG("%s", tmp);
            strcpy(tmp, "");
        } else {
            strcat(tmp, wrap_char2str(rbuff[i]));
            strcat(tmp, " ");
        }
        ++nlc;
    }
    strcpy(tmp, "");
    free(tmp);
}

client clients[MAX_CONN];
int cur_cli_count = 0;

char contains_client(client *cli) {
    for (int i = 0; i < MAX_CONN; ++i) {
        if (cli->cli_addr.sin_addr.s_addr == clients[i].cli_addr.sin_addr.s_addr
            && cli->cli_addr.sin_port == clients[i].cli_addr.sin_port) return 1;

    }
    return 0;
}

int add_client(client *cli) {
    cli = malloc(sizeof(client));
    clients[cur_cli_count++] = *cli;
    return cur_cli_count;
}

void remove_client(int idx) {
    DEBUG("remove_client: %d", idx);
    free(&(clients[idx]));
}

int get_client_index(struct sockaddr_in *cli_addr) {
    for (int i = 0; i < MAX_CONN; ++i) {
        client cur_cli = clients[i];
        if (cli_addr->sin_addr.s_addr == cur_cli.cli_addr.sin_addr.s_addr
            && cli_addr->sin_port == cur_cli.cli_addr.sin_port) return i;

    }
    return -1;
}

client get_client(int idx) {
    return clients[idx];
}

void handle_conn(int conn_fd, struct sockaddr_in *cli_addr) {
    int idx = get_client_index(cli_addr);
    client cli;
    if (idx == -1) {

        idx = add_client(&cli);

        message *msg;
        msg = malloc(sizeof(message));
        msg->source_fd = conn_fd;
        msg->is_fragmented = 0;
        msg->is_handshake = 0;

        cli.cli_addr = *cli_addr;

        handle_handshake_opening(msg);
        DEBUG("connection from %s, port %d (handshake done.)",
              get_conn_addr(cli_addr),
              get_conn_port(cli_addr));

        cli = get_client(idx);
        handle_message(msg);
        remove_client(idx);
    }


}

void handle_message(message *msg) {
    while (1) {
        if (handle_single_frame(msg) == -1) {
            return;
        }
    }

}

int read_into_buffer(message *msg, struct data_frame *df) {
    memset(df->data, 0, MAX_FRAME_SINGLE_BUF_SIZE);
    DEBUG("2: fd %d", msg->source_fd);
    ssize_t rn = read(msg->source_fd, df->data, sizeof(df->data));
    df->cur_buf_len = 0;

    if (rn < 0) {
        ERROR("read_into_buffer error: %zd", rn);
        return (-1);
    }

    df->payload_read_len+=rn;
    df->cur_buf_len = rn;
    DEBUG("read_into_buffer : %zd", rn);

    return (0);
}

int handle_buffer(message *msg, struct data_frame *df) {
    int index;

    index = 0;
    unsigned char cur_byte = df->data[index];
    if (df->frame_header_handled == 0) {
        // Head buffer of frame
        df->fin = (HEX_0xFF & cur_byte) >> FIN_SHIFT_COUNT;

        msg->is_fragmented = df->fin;

        df->opcode = cur_byte << 1;
        df->opcode = df->opcode >> 1;
        DEBUG("opcode: %s", wrap_char2str(df->opcode));

        if (df->opcode == OP_CTRL_CLOSE) {
            return -1;
        }

        cur_byte = df->data[++index];
        // MASK
        df->masked = (HEX_0xFF & cur_byte) >> MASK_SHIFT_COUNT;

        // Payload len byte
        df->payload_len = cur_byte << 1;
        df->payload_len = df->payload_len >> 1;

        DEBUG("Payload len(temp): %d", df->payload_len);

        if (df->payload_len == PL_LEN_VAL_127) {
            // Path 3: Payload len == 127 ext payload len 64 mask start at byte 10
            // combine 8 bytes into final length
            cur_byte = df->data[++index];
            df->payload_final_len = cur_byte;
            df->payload_final_len = df->payload_final_len << 8;

            for (int i = 0; i < 6; ++i) {
                cur_byte = df->data[++index];
                df->payload_final_len += cur_byte;
                df->payload_final_len = df->payload_final_len << 8;
            }

            cur_byte = df->data[++index];
            df->payload_final_len += cur_byte;
        } else if (df->payload_len == PL_LEN_VAL_126) {
            // Path 2: Payload len == 126 ext payload len 16 mask start at byte 4
            // combine 8 bytes into final length
            cur_byte = df->data[++index];
            df->payload_final_len = cur_byte;
            df->payload_final_len = df->payload_final_len << 8;

            cur_byte = df->data[++index];
            df->payload_final_len += cur_byte;
        } else {
            // Path 1: Payload len < 126 mask start at byte 2
            df->payload_final_len = df->payload_len;
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

    int i;
    for (i = index; i < df->cur_buf_len; ++i) {
        cur_byte = df->data[i];

        df->unmasked_payload[df->unmask_buffer_index] = cur_byte ^ (df->mask_key[df->mask_key_index]);
        ++df->mask_key_index;
        if (df->mask_key_index == 4) df->mask_key_index = 0;

    }

    return 1;
}

int handle_single_frame(message *msg) {
    struct data_frame df;
    memset(&df, 0, sizeof(df));

    while (1) {
        // Read until meet max length
        if (read_into_buffer(msg, &df) == -1) {
            ERROR("_handle_single_frame error: -1");
            return (-1);
        }
        DEBUG("cur_buf_len: %llu",  df.cur_buf_len);
        if (df.cur_buf_len == 0) continue;

        if (handle_buffer(msg, &df) == -1) return (-1);

        if (df.payload_read_len == df.payload_final_len) {
            // Single frame read done
            DEBUG("PAYLOAD: %s",  df.unmasked_payload);
            return (1);
        }
    }
}
