//
// Created by lzjlxebr on 5/26/21.
//

#ifndef WEBSOCKET_SERVER_NET_UTIL_H
#define WEBSOCKET_SERVER_NET_UTIL_H

#include <arpa/inet.h>

void get_conn_addr(struct sockaddr_in *addr, char * );
unsigned int get_conn_port(struct sockaddr_in *addr);

#endif //WEBSOCKET_SERVER_NET_UTIL_H
