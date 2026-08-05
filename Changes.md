## 0.1.2 - 2026-08-05

- add datagram length validation to `obfuscate` (short packets are dropped instead of forwarding stale buffer data)
- cap handshake padding so a max-size datagram cannot overflow the scratch buffer (panic)
- hard-cap padded datagrams at the real UDP payload limit (65507 bytes) instead of the buffer size
- only XOR the bytes that will actually be sent when padding handshake packets
- validate incoming packets before allocating a session, preventing resource exhaustion via spoofed sources
- cap sessions per worker (256) so spoofed sources cannot exhaust sockets and tasks
- bind session proxy sockets without holding the sessions lock; keep the worker alive if a bind fails
- clean up sessions when `send_to` fails instead of waiting for the inactivity timeout
- replace `std::hash::DefaultHasher` key derivation with SHA-256 (stable across Rust versions/platforms)
- add unit tests for encode/decode round trips, padded packet handling, wrong-key rejection, and malformed packet rejection

## 0.1.1 - 2025-12-16

- fix compile issue on Windows

## 0.1.0 - 2025-12-16

- first release