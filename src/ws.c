//
// Created by lzjlxebr on 5/24/21.
//

#include "ws.h"
#include "net_util.h"

int handle_handshake_opening(struct message *msg) {
    ssize_t n;
    char req[MAX_HS_REQ_SIZE];
    n = read(msg->fd, &req, sizeof(req));
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

    ssize_t wn = write(msg->fd, res, strlen(res));
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

int read_frame_into_buffer(int fd, struct data_frame *df) {
    ssize_t rn = read(fd, df->data, sizeof(df->data));
    df->cur_byte = NULL;
    if (rn < 0) {
        ERROR("read_frame error: %zd", rn);
        return (-1);
    }
    df->r_count = 0;
    if (rn == 0) {
        return 0;
    }

    dump_data_frame(df);
    DEBUG("read_frame done.");
    return (0);
}

// Read offset bytes from current set
void read_byte_from_frame_by_offset(struct data_frame *df, unsigned char delta_offset) {
    if (df->cur_byte == NULL)
        df->cur_byte = df->data;
    else
        df->cur_byte += delta_offset;
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
    free(tmp);
}

void handle_message_received(struct message *msg) {
    DEBUG("message from %s, port %d (handshake done.)",
          get_conn_addr(&msg->cli_addr),
          get_conn_port(&msg->cli_addr));

    while (1) {
        DEBUG("===============> accept");
        if (handle_data_frame(msg->fd) == -1) {
            break;
        }
        DEBUG("===============> handle_data_frame");
    }
}

int handle_data_frame(int fd) {
    struct data_frame df;
    memset(&df, 0, sizeof(df));

repeat:
    read_frame_into_buffer(fd, &df);
    // FIN and OPCODE byte
    // retrieve fin and opcode
    read_byte_from_frame_by_offset(&df, 0);

    df.fin = (HEX_0xFF & *df.cur_byte) >> FIN_SHIFT_COUNT;

    if (df.fin) {
        // unfragmented frame
    } else {
        // fragmented frame
    }
    df.opcode = *df.cur_byte << 1;
    df.opcode = df.opcode >> 1;
    DEBUG("opcode: %s", wrap_char2str(df.opcode));

    if (df.opcode == OP_CTRL_CLOSE) {
        return -1;
    }

    // MASK and Payload len byte
    read_byte_from_frame_by_offset(&df, 1);
    df.masked = (HEX_0xFF & *df.cur_byte) >> MASK_SHIFT_COUNT;
    df.payload_len = *df.cur_byte << 1;
    df.payload_len = df.payload_len >> 1;

    DEBUG("Payload len(temp): %d", df.payload_len);

    if (df.payload_len == PL_LEN_VAL_127) {
        // Path 3: Payload len == 127 ext payload len 64 mask start at byte 10
        // combine 8 bytes into final length
        read_byte_from_frame_by_offset(&df, 1);
        df.payload_final_len = *df.cur_byte;
        df.payload_final_len = df.payload_final_len << 8;

        for (int i = 0; i < 6; ++i) {
            read_byte_from_frame_by_offset(&df, 1);
            df.payload_final_len += *df.cur_byte;
            df.payload_final_len = df.payload_final_len << 8;
        }

        read_byte_from_frame_by_offset(&df, 1);
        df.payload_final_len += *df.cur_byte;
    } else if (df.payload_len == PL_LEN_VAL_126) {
        // Path 2: Payload len == 126 ext payload len 16 mask start at byte 4
        // combine 8 bytes into final length
        read_byte_from_frame_by_offset(&df, 1);
        df.payload_final_len = *df.cur_byte;
        df.payload_final_len = df.payload_final_len << 8;

        read_byte_from_frame_by_offset(&df, 1);
        df.payload_final_len += *df.cur_byte;
    } else {
        // Path 1: Payload len < 126 mask start at byte 2
        df.payload_final_len = df.payload_len;
    }

    // Masking-key (Extended payload length is 16 or 64)
    int i = 0;
    do {
        read_byte_from_frame_by_offset(&df, 1);
        df.mask_key[i] = *df.cur_byte;
    } while (++i < 4);

    DEBUG("payload_final_len: %llu", df.payload_final_len);
    // unmask data now

    int offset = 1;
    while (1) {
        read_byte_from_frame_by_offset(&df, offset);
        df.unmasked_payload[df.r_count] = *df.cur_byte ^ (df.mask_key[df.r_count % 4]);
        ++df.r_count;

        if (df.r_count == MAX_FRAME_SINGLE_BUF_SIZE) {
            DEBUG("(%d)PAYLOAD: %s", df.r_count, df.unmasked_payload);

            if (df.fin) {
                read_frame_into_buffer(fd, &df);
                offset = 0;
                continue;
            } else {
                goto repeat;
            }
        }
        offset = 1;

        if (df.r_count == df.payload_final_len) {
            break;
        }
    }

    DEBUG("PAYLOAD: %s",  df.unmasked_payload);

    return 0;
}
