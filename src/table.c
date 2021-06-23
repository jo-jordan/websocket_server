//
// Created by lzjlxebr on 6/17/21.
//
#include "table.h"


int add_client(client *cli) {
    for (int i = 0; i < MAX_CONN; i++) {
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
    for (int i = 0; i < MAX_CONN; i++) {
        if (clients[i] == NULL) continue;
        if (clients[i]->uid == uid) {
            clients[i] = NULL;
            --cli_size;
            DEBUG("remove_client: %d", i);
            DEBUG("table size now: %d", cli_size);
            break;
        }
    }
}

client *get_client_by_addr(unsigned long long uid) {
    for (int i = 0; i < MAX_CONN; ++i) {
        client *cli = clients[i];

        if (cli == NULL) continue;
        if (cli->uid == uid) return cli;
    }
    return NULL;
}
