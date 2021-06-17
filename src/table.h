//
// Created by lzjlxebr on 6/17/21.
//

#ifndef WEBSOCKET_SERVER_TABLE_H
#define WEBSOCKET_SERVER_TABLE_H

#include "ws.h"
// Table for connections
int add_client(client*);
client *get_client_by_addr(unsigned long long uid);
void remove_client(unsigned long long uid);


#endif //WEBSOCKET_SERVER_TABLE_H
