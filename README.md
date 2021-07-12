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
let s = new WebSocket('ws://127.0.0.1:9000/')

// Make client listen for message
s.onmessage = (e) => { console.log('message:', e.data) }

// Send message to server
s.send('hello')
```

# TODO List
- [x] Handshake opening
- [x] Handshake closing
- [x] Unmask single frame payload
- [x] Unmask multiple frames payload
- [ ] Ping & Pong 
- [ ] Rules check
- [ ] Security stuff
- [ ] All platform supported (Darwin only maybe for now)
- [ ] Using Event loop (Multiple process for now)
- [ ] Considering distributed situation

