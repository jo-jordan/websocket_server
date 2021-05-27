//
// Created by lzjlxebr on 5/24/21.
//

#include "ws.h"

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

//    if (ws_sec_key == NULL) {
//        ERROR(stderr, "invalid ws header.");
//        exit(-1);
//    }

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

int read_frame(int fd, struct data_frame *df) {
    ssize_t rn = read(fd, df->data, sizeof(df->data));
    if (rn == 0) {
        return 0;
    }
    if (rn < 0) {
        ERROR("read_frame error: %zd", rn);
        return (-1);
    }

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
    for (int i = 0; i < MAX_FRAME_SINGLE_BUF_SIZE; ++i) {
        if (nlc == 3) {
            nlc = -1;
            DEBUG("%s", wrap_char2str(rbuff[i]));
        } else {
            DEBUG("%s", wrap_char2str(rbuff[i]));
        }
        ++nlc;
    }
}

void handle_data_frame(int fd) {
    struct data_frame df;
    memset(&df, 0, sizeof(df));

repeat:
    read_frame(fd, &df);
//    dump_data_frame(&df);
    // FIN and OPCODE byte
    // retrieve fin and opcode
    read_byte_from_frame_by_offset(&df, 0);

    df.fin = (HEX_0xFF & *df.cur_byte) >> FIN_SHIFT_COUNT;
    if (!df.fin) {

    }
    df.opcode = *df.cur_byte << 1;
    df.opcode = df.opcode >> 1;
    DEBUG("opcode: %s", wrap_char2str(df.opcode));

    // MASK and Payload len byte
    read_byte_from_frame_by_offset(&df, 1);
    df.masked = (HEX_0xFF & *df.cur_byte) >> MASK_SHIFT_COUNT;
    df.payload_len = *df.cur_byte << 1;
    df.payload_len = df.payload_len >> 1;

    if (df.payload_len == PL_LEN_VAL_127) {
        // Path 3: Payload len == 127 ext payload len 64 mask start at byte 10
        // combine 8 bytes into final length
        int i = 0;
        do {
            read_byte_from_frame_by_offset(&df, 1);
            df.payload_final_len = *df.cur_byte;
            df.payload_final_len = df.payload_final_len << 8;

            df.payload_final_len += *df.cur_byte;
        } while (++i < 8);
    } else if (df.payload_len == PL_LEN_VAL_126) {
        // Path 2: Payload len == 126 ext payload len 16 mask start at byte 4
        // combine 8 bytes into final length
        int i = 0;
        do {
            read_byte_from_frame_by_offset(&df, 1);
            df.payload_final_len = *df.cur_byte;
            df.payload_final_len = df.payload_final_len << 8;

            df.payload_final_len += *df.cur_byte;
        } while (++i < 2);
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
    do {
        // buffer is so small
        // we should read again and again

        // assume we received a frame that size is 0xFFFFFFFFFFFFFFFF
        // our buffer size is 512
        //        0    0    1
        // frame: [f1] [f2] [f3]


        if (df.r_count >= MAX_FRAME_SINGLE_BUF_SIZE) {
            df.r_count = 0;
            df.cur_byte = NULL;
            DEBUG("PAYLOAD (to be continued): %s",  df.unmasked_payload);
            goto repeat;
        }
        read_byte_from_frame_by_offset(&df, 1);
        df.unmasked_payload[df.r_count] = *df.cur_byte ^ (df.mask_key[df.r_count % 4]);
    } while (++df.r_count < df.payload_final_len);

    DEBUG("PAYLOAD: %s",  df.unmasked_payload);
}
