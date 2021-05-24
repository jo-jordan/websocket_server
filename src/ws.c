//
// Created by lzjlxebr on 5/24/21.
//

#include "ws.h"

void handle_handshake_opening(int fd) {
    ssize_t n;
    char req[MAX_HEADER_LEN];
    n = read(fd, &req, sizeof(req));
    if (n < 0) {
        fprintf(stdout, "read error: %zd", n);
        exit(-1);
    }

    if (n == 0) {
        fprintf(stdout, "read size: %d", 0);
        exit(-1);
    }

    req[n] = '\0';

    char *r = strstr(req, "GET");
    char *sep = "\r\n";
    char *last;

    char *ws_sec_key = NULL;
    unsigned char *result;

    for (char *token = strtok_r(req, sep, &last); token ; token = strtok_r(NULL, sep, &last)) {
        if (strstr(token, WS_SEC_KEY)) {
            ws_sec_key = strtok(token, ": ");
            ws_sec_key = strtok(NULL, ": ");

            printf("We got sec-wb-key: %s\n", ws_sec_key);
            do_sec_key_sha1(ws_sec_key, &result);
            printf("SHA1 result: %s\n", result);
            break;
        }
    }

    char *res;
    res = malloc(MAX_HS_RES_LEN);
    strcpy(res, HANDSHAKE_RES_HEADER);
    strcat(res, (const char *) result);
    strcat(res, "\r\n\r\n");

    ssize_t wn = write(fd, res, strlen(res));
    printf("response(size: %zd): %s", wn, res);

    free(res);

//    if (ws_sec_key == NULL) {
//        fprintf(stderr, "invalid ws header.");
//        exit(-1);
//    }
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
