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
- `TUN_WRITE_FAILED`: VPN interface write failed; stop and restart VPN.
