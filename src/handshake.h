//
// Created by lzjlxebr on 5/23/21.
//

#ifndef WEBSOCKET_SERVER_HANDSHAKE_H
#define WEBSOCKET_SERVER_HANDSHAKE_H

#define HANDSHAKE_REQ_HEADER \
"GET /chat HTTP/1.1 \
Host: server.example.com              \
Upgrade: websocket                    \
Connection: Upgrade                   \
Origin: server.example.com            \
Sec-WebSocket-Key: ddwd3d333d3        \
Sec-WebSocket-Protocol: chat, superchat \
Sec-WebSocket-Version: 17"

#define HANDSHAKE_RES_HEADER \
    "HTTP/1.1 101 Switching Protocols\r\n" \
    "Upgrade: websocket\r\n" \
    "Connection: Upgrade\r\n" \
    "Sec-WebSocket-Accept: "







#endif //WEBSOCKET_SERVER_HANDSHAKE_H
