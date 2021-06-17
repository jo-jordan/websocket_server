#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include "ws.h"
#include "table.h"
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
void sig_child(int signo);
void sig_int(int sig);
void sig_quit(int sig);
void sig_term(int sig);

int connfd, listenfd;

int main() {
    start_serve();
}

void sig_child(int signo) {
    pid_t pid;
    int stat;
    while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
        DEBUG("child %d terminated", pid);
    return;
}

void sig_int(int sig) {
    close(connfd);
    close(listenfd);
    DEBUG("SIGINT: %d", sig);
    exit(0);
}

void sig_quit(int sig) {
    close(connfd);
    close(listenfd);
    DEBUG("SIGQUIT: %d", sig);
    exit(0);
}

void sig_term(int sig) {
    close(connfd);
    close(listenfd);
    DEBUG("SIGTERM: %d", sig);
    exit(0);
}

void start_serve() {
    socklen_t len;
    int end_server, rc, on, timeout, nfds, i;
    int new_fd;
    new_fd = -1;
    on = 1;
    nfds = 1;
    end_server = 0;
    struct pollfd fds[4096];
    const int OPEN_MAX = sysconf(_SC_OPEN_MAX);
    unsigned long long uid = 7;

    // socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    // to reuse local address
    rc = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    if (rc < 0) {
        ERROR("setsockopt() failed: %d", rc);
        close(listenfd);
        exit(-1);
    }

    // make socket nonblocking
    rc = ioctl(listenfd, FIONBIO, (char *)&on);
    if (rc < 0) {
        ERROR("ioctl() failed: %d", rc);
        close(listenfd);
        exit(-1);
    }

    // bind
    struct sockaddr_in serv_addr, cli_addr;
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(9000);
    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        ERROR("bind error");
        exit(-1);
    }

    // listen
    if (listen(listenfd, MAX_LISTEN_Q) < 0) {
        ERROR("listen error");
        exit(-1);
    }

    signal(SIGCHLD, sig_child);
    signal(SIGINT, sig_int);
    signal(SIGQUIT, sig_quit);
    signal(SIGTERM, sig_term);

    memset(fds, 0, sizeof(fds));
    timeout = 60 * 60 * 1000; // timeout based on ms

    fds[0].fd = listenfd;
    fds[0].events = POLLIN;

    DEBUG("server up.");

    do {
        rc = poll(fds, nfds, timeout);
        if (rc < 0) {
            ERROR("poll() failed: %d", rc);
            continue;
        }

        if (rc == 0) {
            ERROR("poll() timeout");
            continue;
        }

        DEBUG("Now ready sockets size %d", nfds);

        if (fds[0].revents & POLLIN) {
            len = sizeof(cli_addr);
            new_fd = accept(listenfd, (struct sockaddr *)&cli_addr, &len);

            if(new_fd < 0) {
                if (errno != EWOULDBLOCK) {
                    ERROR("accept() error");
                    end_server = 1;
                }
                continue;
            }

            DEBUG("New incoming connection - %d", new_fd);
            DEBUG("connection from %s, port %d",
                  get_conn_addr(&cli_addr),
                  get_conn_port(&cli_addr));

            fds[nfds].fd = new_fd;
            fds[nfds].events = POLLIN;
            ++nfds;
            continue;
        }

        for (i = 1; i < nfds; i++) {
            if (fds[i].fd == -1) continue;
            if (fds[i].revents & POLLIN) {
                DEBUG("Descriptor %d is readable", fds[i].fd);

                uid = cli_addr.sin_addr.s_addr;
                uid = (uid << (sizeof(in_port_t) * 8)) + cli_addr.sin_port; /* IP + port */

                client *cli = get_client_by_addr(uid);
                if (cli == NULL || !cli->is_shaken) {
                    rc = handle_handshake_opening(fds[i].fd);
                    if (rc < 0) {
                        ERROR("handle_handshake_opening() failed");

                        close(fds[i].fd);
                        fds[i].fd = -1;
                    }

                    DEBUG("handshake done, uid: %llu", uid);
                    cli = malloc(sizeof(client));
                    cli->cli_addr = cli_addr;
                    cli->uid = uid;
                    cli->is_shaken = 1;
                    add_client(cli);
                } else {
                    rc = handle_conn(fds[i].fd);
                    if (rc == -2) {
                        ERROR("client closed");
                        close(fds[i].fd);
                        remove_client(fds[i].fd);
                        fds[i].fd = -1;
                    }
                }
            }
        }

    } while (!end_server);

    for( i = 0; i < nfds; i++) {
        close(fds[i].fd);
    }
}



/*
Frame format:
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

 mask: 11001000 10000001 10010010 11000010
  XOR  10100000 11100100 11111110 10101110 10100111
  -------------------------------------------
       01101000 01100101 01101100 01101100



 01101000 01100101 01101100 01101100

 */
