//
// Created by lzjlxebr on 6/17/21.
//
#include "table.h"

static client *clients[MAX_CONN];
static int cli_size = 0;

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

void remove_client(int fd) {
    for (int i = 0; i < MAX_CONN; i++) {
        if (clients[i] == NULL) continue;
        if (clients[i]->conn_fd == fd) {
            clients[i] = NULL;
            --cli_size;
            DEBUG("remove_client: %d", i);
            DEBUG("table size now: %d", cli_size);
            break;
        }
    }
}

client *get_client_by_addr(int fd) {
    for (int i = 0; i < MAX_CONN; ++i) {
        client *cli = clients[i];

        if (cli == NULL) continue;
        if (cli->conn_fd == fd) return cli;
    }
    return NULL;
}
