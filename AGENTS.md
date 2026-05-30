# AGENTS.md

## Goal

Refactor and harden the Android project engineering quality for:

```text
D:\work\kcp-proxy-andriod
```

This task is about Android engineering quality, not proxy protocol redesign.

Do not only analyze. Modify code directly.

Keep existing Local Test and Remote Test behavior working.

---

# 0. Baseline Verification

First run:

```bash
./gradlew clean assembleDebug test
```

Record current result.

Then inspect:

```text
settings.gradle
build.gradle
app/build.gradle
gradle.properties
AndroidManifest.xml
KcpVpnService
MainActivity
Fragments
logging
config
threading
tests
docs
```

---

# 1. Gradle / Build Cleanup

## Problems to check

* Hardcoded local JDK path
* Non-portable Gradle settings
* unclear debug/release build config
* missing lint/test workflow
* dependency versions scattered

## Fix

* Remove hardcoded local paths like:

```properties
org.gradle.java.home=C:\Users\...
```

* Keep Gradle config portable.
* Ensure `namespace`, `applicationId`, `compileSdk`, `minSdk`, `targetSdk`, `versionCode`, `versionName` are explicit.
* Add sane debug/release config.
* Ensure release build does not expose verbose packet logs by default.
* Add or fix lint config only if needed.

## Verify

```bash
./gradlew clean assembleDebug test lintDebug
```

---

# 2. Package Name / Namespace

## Problem

If code still uses:

```text
com.example.*
```

that is not production-quality.

## Fix

Rename to a real package, for example:

```text
com.dchen.kcpvpn
```

Update:

```text
namespace
applicationId
AndroidManifest.xml
Java package declarations
imports
test packages
```

## Verify

Search must find no active source references to:

```text
com.example
```

---

# 3. AndroidManifest / Permissions / Foreground Service

## Fix

Review and correct manifest permissions.

Required VPN service rules:

```xml
android:permission="android.permission.BIND_VPN_SERVICE"
android:exported="false"
```

with:

```xml
<action android:name="android.net.VpnService" />
```

Check permissions:

```xml
INTERNET
FOREGROUND_SERVICE
POST_NOTIFICATIONS
```

For Android 14 / targetSdk 34+, foreground services must declare an appropriate foreground service type and related permission when required. See Android’s foreground service type requirements.

Do not add unnecessary dangerous permissions.

## Verify

* App installs.
* VPN permission flow works.
* Foreground notification appears.
* Service starts without Android 13/14 permission crashes.
* If notification permission is denied, app handles it gracefully.

---

# 4. Runtime Permission Flow

## Fix

Ensure UI handles:

```text
VpnService.prepare(...)
POST_NOTIFICATIONS on Android 13+
user denial
```

Do not start VPN if required permission is missing.

Show clear UI message.

## Verify

Test:

```text
fresh install
deny notification permission
deny VPN permission
grant VPN permission
start/stop VPN
```

No crash.

---

# 5. VpnService Lifecycle

## Problems

VPN service may leak resources on stop/revoke/destroy.

## Fix

Audit:

```text
KcpVpnService.onCreate
onStartCommand
onRevoke
onDestroy
startVpn
stopVpn
```

Stop must release:

```text
ParcelFileDescriptor
TUN read/write threads
KCP sessions
UDP sockets
TCP sockets
DNS sockets
Executors
Scheduled tasks
Callbacks/listeners
Notifications
```

Make stop idempotent.

`onRevoke()` must call the same cleanup path.

## Verify

Repeat 5 times:

```text
start Local Test
stop
start Remote Test
stop
revoke VPN permission
rotate screen
kill app
reopen
```

No crash, no thread/socket leak.

---

# 6. Threading / Executors

## Problems

Avoid unmanaged:

```java
new Thread(...)
```

scattered across code.

## Fix

Use named executors:

```text
vpn-read
kcp-update
dns-relay
remote-connect
log-flush
cleanup
```

Prefer:

```java
ExecutorService
ScheduledExecutorService
HandlerThread
```

All executors must be owned by a lifecycle object and shut down on stop.

Socket close should interrupt blocking read.

Unhandled background exceptions must be logged.

## Verify

During browsing:

```text
no unbounded thread growth
stop VPN shuts down threads
restart VPN creates clean new workers
```

---

# 7. Configuration Management

## Fix

Centralize configuration models:

```text
VpnConfig
ServerConfig
KcpConfig
CryptoConfig
DnsConfig
LogConfig
```

Ensure config validation:

```text
mode
serverHost
serverPort
key length
dns servers
mtu
log level
kcp parameters
```

UI should not directly assemble low-level socket/protocol config.

SharedPreferences access should be centralized.

## Verify

* Invalid port rejected.
* Empty key rejected for remote mode.
* Config persists after app restart.
* Switching Local/Remote mode is clean.

---

# 8. Logging Engineering

## Problems

Packet-level logs can cause ANR or leak sensitive data.

## Fix

Implement or verify:

```text
ERROR/WARN/INFO/DEBUG/TRACE levels
debug/trace disabled by default in release
UI log batching every 200-500ms
bounded log buffer
no full payload/key logging
packet trace toggle
export logs feature if already easy
listener callbacks outside synchronized locks
```

## Verify

Browse heavy sites.

```text
no ANR
no log memory growth
UI remains responsive
```

---

# 9. Error Handling

## Fix

Use structured error stages:

```text
VPN_PERMISSION_DENIED
NOTIFICATION_PERMISSION_DENIED
CONFIG_INVALID
SOCKET_PROTECT_FAILED
SERVER_UNREACHABLE
AUTH_FAILED
DNS_FAILED
SOCKS5_FAILED
KCP_TIMEOUT
TUN_WRITE_FAILED
UNKNOWN
```

UI should show:

```text
stage
reason
suggested fix
```

Example:

```text
Remote server unreachable. Check Windows firewall and 10.0.2.2:8388.
```

Do not only show “failed”.

---

# 10. UI Architecture Cleanup

## Fix

Keep this lightweight.

Do not migrate the entire project to Kotlin unless already planned.

Improve Java structure:

```text
Activity: permission/navigation only
Fragment: UI only
ViewModel: UI state
Repository/Controller: service interaction
Service: VPN lifecycle only
Protocol classes: no UI dependency
```

Avoid Fragment directly controlling socket/protocol internals.

If LocalBroadcastManager is used, consider replacing with LiveData/service binding/event repository, or at least isolate it behind one class.

---

# 11. Source Layout

Organize packages clearly.

Suggested structure:

```text
app/
core/
  crypto/
  kcp/
  protocol/
vpn/
  service/
  packet/
  dns/
  tcp/
tunnel/
  local/
  remote/
  cppremote/
data/
  config/
  prefs/
logging/
ui/
  main/
  logs/
  settings/
util/
```

Do not do huge risky moves unless imports/tests remain stable.

---

# 12. Tests

Add or improve unit tests for:

```text
KcpFrameCodec
Crypto
SOCKS5 request builder/parser
DNS packet builder/parser
IPv4 checksum
TCP checksum
UDP checksum
Config validation
```

Add test docs for manual verification.

## Verify

```bash
./gradlew test
```

---

# 13. Documentation

Add/update:

```text
README.md
docs/ARCHITECTURE.md
docs/REMOTE_TEST_WINDOWS.md
docs/TESTING.md
docs/TROUBLESHOOTING.md
```

Include:

```text
how to build
how to run Local Test
how to run Remote Test with kcp-proxy-cpp
Windows firewall notes
Android Emulator uses 10.0.2.2
common failure stages
Chrome test URLs
```

---

# 14. Release Hygiene

## Fix/check

* no hardcoded local machine path
* no committed private keys
* no default verbose packet logs in release
* no test key used silently in release
* ProGuard/R8 config does not break runtime
* debug-only features clearly guarded

---

# 15. Final Verification

Must run:

```bash
./gradlew clean assembleDebug test lintDebug
```

Manual verification:

```text
fresh install
VPN permission flow
notification permission flow
start/stop Local Test
start/stop Remote Test
rotate screen
kill/reopen app
repeat start/stop 5 times
```

If network behavior is available, also verify Chrome browsing still works.

---

# 16. Output Required

At the end, report:

```text
1. Engineering issues found
2. Files changed
3. Fixes completed
4. Tests run and results
5. Lint result
6. Manual verification result
7. Remaining risks
```

Do not stop at advice. Apply fixes directly.