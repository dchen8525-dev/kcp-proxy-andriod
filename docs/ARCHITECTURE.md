# Architecture

KCP VPN is split into four runtime areas:

- `ui`: Activity, fragments, and ViewModel state. UI validates input and requests Android permissions before starting VPN.
- `vpn`: Android `VpnService`, TUN packet routing, lifecycle cleanup, and socket protection.
- `core`: KCP, crypto, protocol codecs, and session primitives with no UI dependency.
- `server` and `vpn.cppremote`: Local Test server path and C++ Remote Test raw SOCKS5-over-KCP path.

Remote Test uses one Chrome TCP connection per `CppRemoteKcpSession`. DNS in remote mode is handled locally through protected UDP sockets.

## Wire protocol (V2)

Both tunnel paths use the same crypto envelope as `kcp-proxy-cpp`:

```
session_salt(16) || nonce(12) || ciphertext || tag(16)
nonce = counter(8, big-endian) || direction(1) || 0x00 0x00 0x00
key   = HKDF-SHA256(PSK, salt=APP_SALT || session_salt, info="kcp-proxy/c2s/v1" | "kcp-proxy/s2c/v1")
counter starts at the first 6 bytes of session_salt (big-endian)
```

- The client generates a fresh random `session_salt` per session. The server learns it from the
  first datagram, derives keys lazily, bypasses the replay window for that packet only, and then
  requires the same salt on every later datagram (`Crypto.matchesSalt`), so traffic from another
  session on the same UDP port cannot be injected.
- The 2048-bit replay window is checked before AEAD verification and committed only after the tag
  verifies; a forged high-counter datagram therefore cannot poison the window.
- PSK and derived key material are zeroed after derivation, so `Crypto` exposes no reset API at all:
  every session gets a fresh instance with a fresh salt. `LocalKcpServer` replaces the session when
  the salt changes (client reconnect on a reused ephemeral port) and rejects a new session whose salt
  already belongs to a live session, which would mean AES-GCM (key, nonce) reuse. A reconnect
  replacement is still allowed when the session cap is reached, because it frees the slot it takes.
- Server-side replacement order mirrors the C++ 0.3.1 fix (e3eff1d): the candidate session must pass
  authentication, salt-uniqueness, AND the salt tombstone before the live session is evicted, so a
  stale handshake retransmit of an older tunnel (its salt is already tombstoned) is refused while
  the live session survives. Pinned by `LocalKcpServerStaleHandshakeTest`.
- Per-candidate `Crypto` isolation mirrors the C++ 0.3.2 fix (3133a1c): a first datagram that fails
  authentication leaves its poisoned learn-salt state inside an instance that `createSession`
  discards immediately; the class refuses re-derivation once the PSK is consumed.

### FEC framing interop (kcp-proxy-cpp 0.3.0+)

The C++ side can wrap each datagram in FEC framing (`FEC header(6) + length(2)` inserted at the
start of the AEAD plaintext, types 0xf1..0xf3 at plaintext bytes 4..5). Framing is per-direction
and auto-adapted per session: the C++ server keeps a session bare when the peer's first datagram is
a bare KCP segment (cmd bytes 0x51..0x54 are disjoint from FEC types). Android never sends FEC
frames, so interop needs no FEC support and the wire stays byte-compatible in both directions.
What Android ports is the diagnostic (`FecFraming.looksLikeFecFrame`): a datagram that decrypts
but is rejected by `kcp.input` and probes as an FEC frame is logged once per session with the
C++-matching wording — that is a FEC configuration mismatch, not key corruption. The receive-side
buffer sizing follows the same rule the C++ 0.3.2 fix (d5bfa44) established: one whole datagram at
the largest legal peer `--mtu` must fit (`SessionConfig.UDP_WIRE_DATAGRAM_MAX = 9052`), because
the kernel silently truncates datagrams that exceed the receive buffer and the AEAD tag then never
verifies — the tunnel looks connected but carries nothing.

Two framings sit on top of that envelope:

- `vpn/cppremote`: one local TCP connection = one `CppRemoteKcpSession` = one UDP socket = one KCP
  session. First KCP message is `KCP_PROXY_HELLO_V2`, the server mirrors `KCP_PROXY_HELLO_ACK_V2`
  (which enables half-close), then the client sends the SOCKS5 CONNECT and the rest of the stream is
  raw TCP bytes. Keepalive and FIN are `magic || session_salt` matched by exact length and content,
  and are stripped before the SOCKS5 parser and before anything is written to the TUN. A local FIN
  half-opens the session (drain remaining server data, 120s grace) instead of closing the socket.
- Local Test (`server` + `vpn/TunnelManager`): one shared session carrying `KcpFrame` messages
  (`OPEN` / `DATA` / `CLOSE` / `RESET` / `UDP_DATAGRAM` / `PING` / `PONG`). Liveness comes from the
  periodic PING/PONG, so no crypto-layer keepalive is needed on this path.

### TCP half-close sequence

`PacketRouter` mirrors real TCP so Chrome cannot lose the last bytes of a response:

1. Client FIN from the app → outbound `CLOSE`/half-close is sent once (`clientFinSeen` guards
   retransmitted FINs) and the TUN only receives an `ACK` (flags `0x10`). The Android session and
   `TcpConnection` stay alive; `serverNextSeq` is not advanced.
2. Data that the target still sends is written to the TUN normally (flags `0x18`).
3. When the remote side closes (server FIN / `CLOSE` frame / session close callback) the router
   writes the single FIN (flags `0x11`, `serverNextSeq += 1`) and removes the connection. A
   failure reason sends RST (flags `0x14`) instead.
4. Idle `CLOSING` connections are reclaimed after 150s, longer than the 120s session drain grace, and
   the cleanup path goes through `sendCloseToOutbound` so Remote Test really closes the KCP session
   (a raw `KcpFrame` is dropped in CPP_REMOTE mode and would leak the session plus its UDP socket).

Datagrams that fail AEAD verification are dropped, not fatal: `CppRemoteKcpSession` only reports
`CRYPTO_MISMATCH` after 8 consecutive auth failures, matching the C++ server, so a stray or forged
packet cannot tear down a working connection.

### Send-side backpressure

The TUN side acknowledges every byte Chrome writes, so Chrome never sees the tunnel's congestion and
`Kcp.send` would keep appending to `snd_queue` without limit. `CppRemoteKcpSession` therefore bounds
its own output: `sendRaw` writes straight into KCP only while the outbound queue is empty and
`waitSend() < KcpConfig.KCP_BACKPRESSURE_THRESHOLD`; otherwise the bytes are queued in order (once
queued, everything follows, because KCP is a byte stream and inserting would corrupt it) and the KCP
update tick drains them as the window frees. The queue is capped at 2 MiB; exceeding it means the
link has stalled beyond recovery, so the session closes with `KCP_BACKPRESSURE_OVERFLOW` instead of
growing unbounded.

Release builds compile with `BuildConfig.DEFAULT_LOG_LEVEL=INFO` and `PACKET_TRACE_ENABLED=false`.
`PACKET_TRACE_ENABLED` gates only the TUN packet-layer traces (`TCP IN` / `TCP OUT` / `UDP IN` /
`UDP OUT`, one per packet, UDP sampled 1/64) inside `Logger.packetTrace(...)`; every other diagnostic
follows the log level alone. Debug builds keep both available.
