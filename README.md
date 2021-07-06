# WebSocket Server 
Implements according to [RFC6455](https://datatracker.ietf.org/doc/rfc6455/).

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

