# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Android KCP VPN application for API 30+ (Android 11+). Implements global traffic proxy via VpnService with KCP tunnel. Pure Java 8 implementation compatible with C++ kcp-proxy-cpp server. No Kotlin, no third-party proxy cores.

**Key constraint**: All protocol parameters must match C++ kcp-proxy-cpp exactly for interoperability.

## Build Commands

```bash
# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Clean build
./gradlew clean
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

No unit tests exist yet (`app/src/test/` is absent). Instrumentation tests would use `./gradlew connectedAndroidTest`.

## Architecture

### Package Structure (under `com.dchen.kcpvpn`)

```
core/     - Pure Java, no Android dependencies (KCP, Crypto, SOCKS5, Session)
  kcp/        - KCP protocol: Kcp.java, Segment.java, AckList.java, KcpConfig.java
  crypto/     - HKDF-SHA256 + AES-128-GCM: Crypto.java, AesGcmCipher.java, HkdfSha256.java, NonceGenerator.java, ReplayWindow.java
  protocol/   - SOCKS5: Socks5.java, Socks5Request.java, Socks5Response.java, AddressParser.java, AddressEncoder.java
  session/    - KcpClientSession.java, SessionConfig.java, SessionState.java
vpn/      - Android VpnService: KcpVpnService → TunnelManager → PacketRouter
server/   - Built-in local KCP server for self-testing: LocalKcpServer, ServerSession, Socks5Handler
ui/       - Material Design 3: MainActivity → MainFragment + LogFragment, MainViewModel
log/      - Rolling log storage (10MB disk, 500 entries in memory): Logger, LogWriter, LogBuffer
util/     - ByteUtils, NetworkUtil, ServiceUtil
```

### Data Flow

**Outbound (Phone → Internet)**:
```
VPN Interface → PacketRouter → SOCKS5 Request → KcpClientSession → Crypto.encrypt → UDP
```

**Inbound (Internet → Phone)**:
```
UDP → Crypto.decrypt → KCP.input → KCP.recv → PacketRouter → VPN Interface
```

PacketRouter maintains a `ConcurrentHashMap<Integer, SocketConnection>` keyed by `Arrays.hashCode(dstAddr) * 31 + dstPort` to track active TCP connections multiplexed over the single KCP tunnel.

### Critical Protocol Parameters (must match C++)

| Parameter | Value | Location |
|-----------|-------|----------|
| KCP_INTERVAL | 10ms | KcpConfig |
| KCP_SNDWND | 256 | KcpConfig |
| KCP_RCVWND | 512 | KcpConfig |
| KCP_MTU | 1400 | KcpConfig |
| KCP_TIMEOUT | 60s | KcpConfig |
| KCP nodelay | enabled, interval=10, fastresend=5, nocwnd=1 | KcpConfig |
| Default conv | 1 | KcpConfig |
| Backpressure threshold | 512 (= SNDWND * 2) | KcpConfig |
| APP_SALT | "kcp-proxy-hkdf-salt-v1" | CryptoConfig |
| HKDF info C2S | "kcp-proxy/c2s/v1" | CryptoConfig |
| HKDF info S2C | "kcp-proxy/s2c/v1" | CryptoConfig |
| Nonce format | 8-byte counter + 1-byte direction + 3-byte zero padding | NonceGenerator |
| Nonce direction | CLIENT=0x01, SERVER=0x02 | CryptoConfig |
| AES key size | 128-bit (16 bytes) | CryptoConfig |
| Max counter | 2^48 (IND-CPA safety limit) | CryptoConfig |
| Replay window | 64 bits | ReplayWindow / CryptoConfig |

### Crypto Flow

```
UserKey + UserSalt + APP_SALT → HKDF-SHA256 → AES-128 key (per direction)
Encrypt: plaintext → AES-128-GCM → [nonce(12)] + [ciphertext] + [tag(16)]
Decrypt: validate nonce direction → replay check → AES-GCM decrypt
```

### Dual Mode Operation

1. **Remote mode**: Connect to external kcp-proxy-cpp server (user provides IP, port, key)
2. **Local test mode**: Built-in LocalKcpServer starts on `127.0.0.1:8443`, client connects to it

### VPN Service Lifecycle

- `onCreate()`: Initialize state (Logger already initialized in Application)
- `onStartCommand()`: Extract intent extras (server_host, server_port, key, local_mode), start foreground notification within 5 seconds (Android 11+ requirement), establish VPN interface
- `onDestroy()`: Stop KCP, close VPN interface
- `onRevoke()`: User revoked VPN permission → immediate stop

### Reconnection Strategy

Exponential backoff in TunnelManager (AtomicInteger for thread safety):
- Initial: 1s → 2s → 4s → 8s → 16s → 32s → max 60s
- Reset on successful connection

### Session Management

- `KcpClientSession`: Client-side KCP with UDP DatagramSocket, update thread (10ms interval), receive thread. Uses volatile fields for cross-thread visibility of pending read buffers.
- `ServerSession`: Server-side KCP with backpressure control (pause TCP read when KCP queue > 512)

### Log Module Identifiers

Use `LogConfig.MODULE_*` constants: `vpn`, `kcp_client`, `kcp_server`, `crypto`, `socks5`, `ui`, `reconnect`

## Android 11+ Requirements

- `foregroundServiceType="dataSync"` in manifest
- `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_DATA_SYNC` permissions
- VPN authorization via `VpnService.prepare()` before starting service
- Notification ID 1001 (`VpnConfig.NOTIFICATION_ID`) must remain visible during VPN operation
- VPN interface uses address `10.0.0.2/32`, MTU matches KCP_MTU (1400)

## Java 8 Constraint

`compileOptions` targets Java 1.8. The `core/` package is pure Java with no Android dependencies and must not use Java 9+ APIs (no `List.of()`, no `var`, no `ProcessHandle`).

## Testing Compatibility with C++ Server

When making changes to protocol logic, verify against the C++ reference implementation:
1. CryptoConfig constants match `native/core/include/kcp_proxy/config.hpp`
2. Crypto.java logic matches `native/core/src/crypto.cpp`
3. SOCKS5 format matches `native/core/src/socks5.cpp` and `address.cpp`
4. KCP parameters match `native/third_party/kcp/ikcp.h` defaults
