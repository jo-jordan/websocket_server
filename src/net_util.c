//
// Created by lzjlxebr on 5/26/21.
//

#include "net_util.h"

const char* get_conn_addr(struct sockaddr_in *addr) {
    char buff[64];
    return inet_ntop(AF_INET, &addr->sin_addr, buff, sizeof(buff));
}

unsigned int get_conn_port(struct sockaddr_in *addr) {
    return ntohs(addr->sin_port);
}

