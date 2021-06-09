//
// Created by lzjlxebr on 6/4/21.
//

#ifndef WEBSOCKET_SERVER_BUF_H
#define WEBSOCKET_SERVER_BUF_H

#include <unistd.h>

// plunder from fd to size target buffer
// target's length equals size
// read will resume from the last time this subroutine called
void plunder(unsigned char*, size_t, int, unsigned int);

void plunder(unsigned char* target, size_t target_size, int fd, unsigned int *last_index) {

    int rn = read(fd, target, target_size);
    if (rn == 0) return; // read done
    if (rn < 0) return; // read error TODO handle error

    *last_index = rn;
}


#endif //WEBSOCKET_SERVER_BUF_H
