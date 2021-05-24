#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include "ws.h"


/*
 * handshake
 * - opening handshake
 * -
 * - handshake response
 *
 * data swiping
 * - data framing
 * */
int main() {
    int connfd, listenfd;
    socklen_t len;
    char buff[MAX_HEADER_LEN];
    time_t ticks;
    pid_t pid;

    // socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    // bind
    struct sockaddr_in serv_addr, cli_addr;
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(9000);
    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        exit(0);
    }

    // listen
    if (listen(listenfd, MAX_LISTEN_Q) < 0) {
        exit(0);
    }
    printf("server up.\n");

    for (;;) {
        len = sizeof(cli_addr);
        // accept
        connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &len);

        printf("connection from %s, port %d\n",
               inet_ntop(AF_INET, &cli_addr.sin_addr, buff, sizeof(buff)),
               ntohs(cli_addr.sin_port));

        handle_handshake_opening(connfd);

        printf("");

//        close(connfd);
//        exit(0);
    }


    exit(0);
}
