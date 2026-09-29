# Troubleshooting

Common stages:

- `VPN_PERMISSION_DENIED`: grant Android VPN permission.
- `NOTIFICATION_PERMISSION_DENIED`: allow notifications on Android 13+ before starting VPN.
- `CONFIG_INVALID`: check host, port, and key.
- `SOCKET_PROTECT_FAILED`: socket may be routed back into the VPN; restart VPN and check service logs.
- `SERVER_UNREACHABLE`: check `10.0.2.2:8388`, Windows Firewall, and C++ server status.
- `AUTH_FAILED`: verify both sides use the same key.
- `DNS_FAILED`: verify network DNS or fallback DNS reachability.
- `SOCKS5_FAILED`: C++ server rejected or failed target connection.
- `KCP_TIMEOUT`: check UDP connectivity and packet loss.
- `KCP_BACKPRESSURE_OVERFLOW`: the link could not drain the outbound queue and 2 MiB of queued
  bytes was exceeded. The affected TCP connection is closed (Chrome retries it); check UDP
  connectivity and packet loss rather than the key.
- `TUN_WRITE_FAILED`: VPN interface write failed; stop and restart VPN.
- `CRYPTO_MISMATCH`: 8 consecutive datagrams failed AEAD verification. Almost always the pre-shared
  key, or a server that predates the V2 wire format
  (`session_salt(16) || nonce(12) || ciphertext || tag(16)`). Rebuild or upgrade the C++ server
  rather than the client. A single bad packet never closes a session.

Protocol notes:

- Replayed or reordered datagrams are not failures. The 2048-bit replay window absorbs UDP
  reordering; a rejected datagram is dropped at DEBUG level and the session keeps running.
- A `session salt mismatch` error means a datagram on a known UDP source port carries a different
  per-session salt. In Remote Test the C++ server replaces the session (client reconnect on a
  reused ephemeral port); in Local Test the same happens after the new packet authenticates, so a
  wrong-key packet cannot tear down a live session.
- Keepalive and FIN carry `magic || session_salt` and are removed before tunnel data. If tunnel
  bytes start disappearing, check that a control message is not being forwarded into the TUN.
- `Session cap reached` in Local Test only blocks brand-new sessions. A reconnect that replaces the
  session on the same UDP source port is still accepted, because it frees the slot it consumes.
- Under sustained loss the Remote Test outbound queue fills up before the window does, which shows
  as `CPP_REMOTE outbound queued by backpressure` at DEBUG. Seeing it briefly is normal congestion;
  seeing it until `KCP_BACKPRESSURE_OVERFLOW` means the UDP path is effectively dead.
