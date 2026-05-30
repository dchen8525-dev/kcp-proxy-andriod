# Architecture

KCP VPN is split into four runtime areas:

- `ui`: Activity, fragments, and ViewModel state. UI validates input and requests Android permissions before starting VPN.
- `vpn`: Android `VpnService`, TUN packet routing, lifecycle cleanup, and socket protection.
- `core`: KCP, crypto, protocol codecs, and session primitives with no UI dependency.
- `server` and `vpn.cppremote`: Local Test server path and C++ Remote Test raw SOCKS5-over-KCP path.

Remote Test uses one Chrome TCP connection per `CppRemoteKcpSession`. DNS in remote mode is handled locally through protected UDP sockets.

Release builds use `BuildConfig.DEFAULT_LOG_LEVEL=INFO` and `PACKET_TRACE_ENABLED=false`; debug builds keep verbose diagnostics available.
