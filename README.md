# WebSocket Server 
Implements according to [RFC6455](https://datatracker.ietf.org/doc/rfc6455/).

# Quick start
## Build
```shell
git clone https://github.com/lzjlxebr/websocket_server.git
cd ./websocket_server
mkdir build && cd $_
cmake .. -DCMAKE_C_COMPILER=gcc
make
```
## Run server
```shell
./websocket_server
```
## Run client in a browser
```javascript
// Make a WebSocket client
let ws = new WebSocket('ws://127.0.0.1:9000/')

// Make client listen for message
ws.onmessage = (e) => { console.log('message:', e.data) }
ws.onclose = (e) => { console.log('message:', e) }

// Send message to server
ws.send('hello')

// Close conncetion
ws.close()
```

# TODO List
- [x] Handshake opening
- [x] Handshake closing
- [x] Receiving data from client
    - [x] Unmask single frame payload
    - [x] Unmask multiple frames payload
    - [x] Ping & Pong
- [x] Sending data to client
- [ ] All platform supported
    - [x] Linux
    - [x] Darwin
    - [ ] Windows
- [ ] Using Event loop with Reactor pattern
    - [x] Multiple process for now
    - [x] Using system call `poll`
    - [ ] Event loop
- [ ] RFC6455 validations
- [ ] Security stuff
- [ ] Considering distributed situation

