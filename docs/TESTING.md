# Testing

Build and unit test:

```bash
./gradlew clean assembleDebug test lintDebug
```

Manual checks:

- Fresh install.
- Deny notification permission: app should show `NOTIFICATION_PERMISSION_DENIED` and not start VPN.
- Deny VPN permission: app should stay disconnected and show a clear message.
- Grant VPN permission and start Local Test.
- Stop Local Test.
- Start Remote Test with `10.0.2.2:8388`.
- Rotate screen while connected.
- Kill and reopen the app.
- Repeat start/stop five times.

Browser URLs:

- `http://neverssl.com`
- `http://example.org`
- `https://example.com`
- `https://www.cloudflare.com`
- `https://www.wikipedia.org`
- `https://httpbin.org/get`
