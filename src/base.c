//
// Created by lzjlxebr on 5/26/21.
//


#include "base.h"

char* wrap_char2str(const unsigned char in) {
    char *out;
    out = malloc(8 * sizeof(char));
    for (int i = 7; i >= 0; --i) {
        const char *t = (in & (1 << i)) ? "1" : "0";
        strcat(out, t);
    }
    strcat(out, "");
    return out;
}

