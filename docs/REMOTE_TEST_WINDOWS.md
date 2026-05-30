# Remote Test on Windows

Start the C++ server on Windows:

```bat
cd /d D:\work\kcp-proxy-cpp
bin\windows\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
netstat -ano -p udp | findstr 8388
```

In the Android emulator, use:

- Host: `10.0.2.2`
- Port: `8388`
- Key: `remote_test_key_123456`

`10.0.2.2` is the Android Emulator route to the Windows host. Do not use `127.0.0.1` for the Windows server from inside the emulator.

If packets do not arrive, check Windows Firewall for inbound UDP 8388.

Expected Android INFO logs:

```text
mode=CPP_REMOTE server=10.0.2.2:8388 protocol=socks5-over-kcp-raw-stream socketProtected=true
CPP_REMOTE KCP conv=1 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 mtu=1400 timeout=60s
CPP_REMOTE state=STARTED detail=local VPN/tunnel manager started
CPP_REMOTE SOCKS5 CONNECT connectionId=<id> dst=<ip>:<port>
CPP_REMOTE SOCKS5 response rep=0x00 connectionId=<id>
CPP_REMOTE state=REMOTE_REACHABLE detail=valid SOCKS5 response received
```

Expected C++ INFO logs:

```text
listening on 0.0.0.0:8388
diagnostics udp_bind=0.0.0.0 udp_port=8388 crypto=AES-128-GCM/HKDF-SHA256 socks5_mode=CONNECT_ONLY
KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s
new session: <emulator-endpoint> (total: 1)
SOCKS5 CONNECT dst=<ip>:<port> cmd=1
connected to target <ip>:<port>
```

Chrome test URLs:

```text
http://93.184.216.34
http://neverssl.com
http://example.org
https://example.com
https://www.cloudflare.com
https://www.wikipedia.org
https://httpbin.org/get
```

Concurrent tabs:

```text
https://www.google.com
https://www.github.com
https://www.wikipedia.org
https://www.cloudflare.com
```

Failure stage mapping:

```text
CPP_SERVER_NO_PACKET     No UDP packet reached the Windows server; check firewall and 10.0.2.2:8388.
CPP_SERVER_NO_RESPONSE   Android sent UDP but no usable response arrived before the receive path failed.
CRYPTO_MISMATCH          Key, HKDF, nonce direction, or AES-GCM tag does not match the C++ server.
SOCKS5_RESPONSE_FAILED   Server response was malformed or fragmented beyond valid SOCKS5 parsing.
SOCKS5_CONNECT_FAILED    Server returned a non-zero SOCKS5 REP.
```

Android INFO logs are intentionally lifecycle-only. Packet events such as TUN reads, VPN writes,
UDP sends, KCP payload movement, and SOCKS5 hex dumps are DEBUG.
