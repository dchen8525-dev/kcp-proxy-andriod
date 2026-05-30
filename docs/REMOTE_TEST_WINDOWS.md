# Remote Test on Windows

Start the C++ server on Windows:

```bat
cd /d D:\work\kcp-proxy-cpp
bin\windows\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L DEBUG
netstat -ano -p udp | findstr 8388
```

In the Android emulator, use:

- Host: `10.0.2.2`
- Port: `8388`
- Key: `remote_test_key_123456`

`10.0.2.2` is the Android Emulator route to the Windows host. Do not use `127.0.0.1` for the Windows server from inside the emulator.

If packets do not arrive, check Windows Firewall for inbound UDP 8388.
