# Testing

Build and unit test:

```bash
./gradlew clean assembleDebug test lintDebug
```

## Running tests without an Android SDK

Two fallbacks exist for machines where the Google SDK repositories are unreachable
(verified working on the current dev box):

1. **Assemble an SDK from a mirror.** Tencent mirrors the SDK packages at
   `https://mirrors.cloud.tencent.com/AndroidSDK/` (e.g. `platform-34-ext7_r02.zip`,
   `build-tools_r34-windows.zip`, `platform-tools_r34.0.5-windows.zip`). Unzip them into
   `%LOCALAPPDATA%\Android\Sdk` as `platforms/android-34`, `build-tools/34.0.0`,
   `platform-tools`, write the standard license hashes into `licenses/android-sdk-license`,
   and install the aapt2 binary artifact (from the Aliyun google mirror,
   `com.android.tools.build:aapt2:<agp>-<build>:windows`) into `~/.m2` — the project's
   `settings.gradle` already checks `mavenLocal()` first. `app/build.gradle` pins
   `buildToolsVersion "34.0.0"` so AGP does not demand a build-tools version the mirror
   does not have.

2. **Pure-JVM harness** (no Android at all): `.jvmtest/run.sh` compiles the pure-Java
   subset of main sources with the stub `Logger` in `.jvmtest/stub/` and runs every
   plain-JVM unit test with JUnit 4. Covers crypto, KCP, protocol codecs, config, the
   local server and `PacketRouter`/tunnel logic — everything except code that imports
   `android.*` directly.

## Unit test coverage

| Test | What it pins down |
|------|-------------------|
| `core/crypto/HkdfSha256Test` | RFC 5869 case 1 plus the project's own C2S/S2C session keys, compared against an independent HKDF implementation |
| `core/crypto/CryptoV2InteropTest` | The V2 wire format byte-for-byte against vectors generated outside the app: salt prefix, nonce layout, counter seeded from `session_salt`, direction separation, lazy server derivation, salt-mismatch rejection, replay rejection, and that a forged packet cannot poison the replay window (commit happens after AEAD verify) |
| `core/crypto/ReplayWindowTest` | 2048-bit window edges, `check()` being read-only, sliding, and jump behaviour |
| `vpn/cppremote/CppControlMessageTest` | `magic \|\| session_salt` control messages match exactly, tunnel data that merely starts with the magic is never dropped, and the magics match `config.hpp` |
| `vpn/PacketRouterHalfCloseTest` | The fake-TCP half-close order: an app FIN produces one outbound `CLOSE` and an `ACK` only (no premature FIN), server data that arrives afterwards still reaches the TUN, and exactly one FIN is written when the remote closes; a retransmitted FIN does not duplicate the `CLOSE` |
| `vpn/cppremote/CppBackpressureTest` | The outbound `waitSend()` threshold: it leaves room for one whole message inside `KCP_SNDWND` and flips exactly at `KCP_BACKPRESSURE_THRESHOLD` |
| `core/protocol/*`, `core/kcp/*`, `vpn/cppremote/CppSocks5ResponseBufferTest`, `data/config/*` | Frame codec, KCP input, SOCKS5 reply buffering, config validation |

The crypto vectors are the interop contract: if `kcp-proxy-cpp` changes its salt, nonce, HKDF label
or window rules, `CryptoV2InteropTest` fails before a device is involved.

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

Protocol checks (V2):

- Remote Test: the C++ server logs `KCP handshake confirmed (V2, half-close enabled)` for each new
  connection and the client logs `CPP_REMOTE handshake confirmed (V2, half-close enabled)`.
- Idle a connection for more than 30s: client logs `CPP_REMOTE keepalive sent`, server logs
  `keepalive received, dropping` (DEBUG), and no keepalive bytes reach the browser.
- Type a URL then close the tab while a large download is still in flight: client logs
  `CPP_REMOTE FIN sent (half-close)`, server logs `client FIN received, closing target write side`,
  and the already-queued response bytes still reach the browser before the session is torn down.
  The browser sees its own FIN answered with an `ACK` first, and only one FIN when the remote closes.
- Inbound half-close: when the target closes first the server sends its FIN and the client logs
  `CPP_REMOTE server FIN received (target half-closed)`; the TUN sees a FIN, not stray payload.
- Stop and restart the VPN (the emulator may reuse its source UDP port): the C++ server creates a
  new session instead of logging repeated decrypt failures, which is what a broken salt-mismatch
  path looks like.
- Start Remote Test against a V1-only server: the client logs `handshake confirmed (V1 server,
  half-close disabled)` and browsing still works.

Browser URLs:

- `http://neverssl.com`
- `http://example.org`
- `https://example.com`
- `https://www.cloudflare.com`
- `https://www.wikipedia.org`
- `https://httpbin.org/get`
