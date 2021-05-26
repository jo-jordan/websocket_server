#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include "ws.h"
#include "base.h"
#include "net_util.h"


/*
 * handshake
 * - opening handshake
 * - handshake response
 * - closing handshake
 *
 * data swiping
 * - data framing
 * - unmask frame
 * */
void start_serve();

int main() {
    start_serve();
}

void start_serve() {
    int connfd, listenfd;
    socklen_t len;

    char isHandshake = 0;

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
    DEBUG("server up.");

    for (;;) {
        len = sizeof(cli_addr);
        // accept
        connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &len);

        DEBUG("connection from %s, port %d",
               get_conn_addr(&cli_addr),
               get_conn_port(&cli_addr));

        if (!isHandshake && handle_handshake_opening(connfd) < 0) {
            close(connfd);
            exit(0);
        }

        isHandshake = 1; // TODO change to event loop

        while (1) {
            DEBUG("===============> accept");
            handle_data_frame(connfd);
            DEBUG("===============> handle_data_frame");
        }

    }
}



/*
Frame format:
      1 0 0 0 0 0 0 1 1 0 0 0 0 1 0 1 1 0 1 0 1 0 0 0 1 0 0 0 0 1 0 1
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

     +-+-+-+-+-------+-+-------------+-------------------------------+
     |000000000000000|111111111111111|22222222222222|3333333333333333|
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |444444444444444|555555555555555|66666666666666|7777777777777777|
     + - - - - - - - - - - - - - - - +-------------------------------+
     |888888888888888|999999999999999|10101010101010|11______________|
     +-------------------------------+-------------------------------+
     |12_____________|13_____________|14____________|15______________|


01101111 00000000 00000000 00000000

 mask: 00000000 10110101 01000100 00110101
  XOR  01101000 11010000 00101000 01011001
  -------------------------------------------
       01101000 01100101 01101100 01101100



 01101000 01100101 01101100 01101100

 */
