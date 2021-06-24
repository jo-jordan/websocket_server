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
#include <sys/syslimits.h>
#include "ws.h"
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


int main() {
    start_serve();
}

void sig_child(int signo) {
    pid_t pid;
    int stat;
    while((pid = waitpid(-1, &stat, WNOHANG)) > 0)
        DEBUG("child %d terminated", pid);
}

void start_serve() {
    int test = 0b11111111;
    DEBUG("%d", test &= ~(1UL << 7));
    socklen_t len;
    struct pollfd fds[OPEN_MAX];
    unsigned long long uid = 7;
    struct sockaddr_in serv_addr, cli_addr;

    int end_server, rc, on, timeout, nfds, i , maxi, n_ready;
    int listenfd;
    int new_fd = -1; /* for new incoming connection */
    int sock_fd = -1;
    on = 1;
    nfds = 1; /* The nfds argument specifies the size of the fds array. */
    end_server = 0;
    n_ready = 0; /* each poll */
    timeout = -1; /* timeout based on ms, INFTIM = -1 */

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

    memset(fds, 0, sizeof(fds));

    fds[0].fd = listenfd; /* The first poolfd is always ths listening fd */
    fds[0].events = POLLRDNORM;

    for (i = 1; i < OPEN_MAX; i++) fds[i].fd = -1; /* -1 indicates available entry */

    maxi = 0; /* max index into fds[] array */

    DEBUG("server up.");
    do {
        n_ready = poll(fds, maxi + 1, timeout);

        DEBUG("Now ready sockets size %d", nfds);

        if (fds[0].revents & POLLRDNORM) {
            len = sizeof(cli_addr);
            new_fd = accept(listenfd, (struct sockaddr *)&cli_addr, &len);
            if(new_fd < 0) {
                if (errno != EWOULDBLOCK) {
                    ERROR("accept() error");
                    end_server = 1;
                }
                continue;
            }

            for (i = 1; i < OPEN_MAX; i++)
                if (fds[i].fd < 0) {
                    fds[i].fd = new_fd;
                    break;
                }
            if (i == OPEN_MAX) {
                ERROR("too many clients.");
                exit(-1);
            }
            fds[i].events = POLLRDNORM;

            if (i > maxi)
                maxi = i;

            DEBUG("New incoming connection - %d", new_fd);
            DEBUG("connection from %s, port %d",
                  get_conn_addr(&cli_addr),
                  get_conn_port(&cli_addr));

            client *cli;
            uid = cli_addr.sin_addr.s_addr;
            uid = (uid << (sizeof(in_port_t) * 8)) + cli_addr.sin_port; /* IP + port */
            cli = malloc(sizeof(client));
            cli->cli_addr = cli_addr;
            cli->uid = uid;
            cli->is_shaken = 0;
            cli->fd = new_fd;
            add_client(cli);

            if (--n_ready < 0) continue; /* no more readable fd, decrease means we already handle one */
        }

        for (i = 1; i <= maxi; i++) {
            if ((sock_fd = fds[i].fd) < 0) continue;

            if (fds[i].revents & (POLLHUP)) {
                goto close_cli;
            }
            if (fds[i].revents & (POLLRDNORM | POLLERR)) {
                DEBUG("Descriptor %d is readable", fds[i].fd);

                client *cli = get_client_by_addr(uid);
                if (!cli->is_shaken) {
                    rc = handle_handshake_opening(fds[i].fd);
                    if (rc < 0) {
                        ERROR("handle_handshake_opening() failed");

                        close(fds[i].fd);
                        fds[i].fd = -1;
                    }

                    DEBUG("handshake done, uid: %llu", uid);
                    cli->is_shaken = 1;
                } else {
                    rc = handle_conn(sock_fd);
                    if (rc == -1) goto close_cli;

                    if (rc == -2) {
                        goto close_cli;
                    }
                    if (--nfds <= 0)
                        continue;
                }
            }
            continue;
        close_cli:
            --nfds;
            ERROR("client closed");
            close(fds[i].fd);
            remove_client(fds[i].fd);
            fds[i].fd = -1;
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


0x81     0x06 48 65 6C 6C 6F
10000001 00000110
01101111 00000000 00000000 00000000

 mask: 11001000 10000001 10010010 11000010
  XOR  10100000 11100100 11111110 10101110 10100111
  -------------------------------------------
       01101000 01100101 01101100 01101100



 01101000 01100101 01101100 01101100

 */
