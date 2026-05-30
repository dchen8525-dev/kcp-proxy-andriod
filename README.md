# KCP VPN Android

Android 11+ (API 30) 全局 KCP 隧道 VPN 应用。基于原生 VpnService 实现整机流量代理，纯 Java 实现，与 C++ [kcp-proxy-cpp](https://github.com/skywind3000/kcp) 服务端完全兼容。

## 功能特性

- **双模式运行**
  - 外网模式：连接远程 KCP 服务端（用户配置 IP、端口、密钥）
  - 本地自测模式：内置 KCP 服务端（`127.0.0.1:8443`），本机闭环测试

- **协议兼容**
  - KCP 参数与 C++ 版本完全一致（MTU=1400, SNDWND=256, RCVWND=512）
  - HKDF-SHA256 密钥派生 + AES-128-GCM 加密 + 64-bit 重放防护
  - SOCKS5 代理协议

- **完整日志系统**
  - 分级日志（Debug/Info/Warning/Error）
  - 界面实时显示（500 条缓冲）
  - 本地循环存储（10MB 上限，双文件轮转）

- **Android 11+ 适配**
  - 前台服务通知（`foregroundServiceType="dataSync"`）
  - VPN 权限处理（`VpnService.prepare()`）
  - 指数退避重连（1s → 2s → ... → max 60s）

## 编译运行

### Android Studio

1. 安装 [Android Studio](https://developer.android.com/studio)
2. `File → Open → 选择项目目录`
3. 等待 Gradle 同步完成
4. `Build → Build Bundle(s) / APK(s) → Build APK(s)`
5. APK 输出：`app/build/outputs/apk/debug/app-debug.apk`

### 命令行

```bash
export ANDROID_HOME=/path/to/Android/Sdk
./gradlew assembleDebug
# APK 输出: app/build/outputs/apk/debug/app-debug.apk
```

完整验证：

```bash
./gradlew clean assembleDebug test lintDebug
```

## 使用说明

### 外网模式

1. 启动远程 KCP 服务端（kcp-proxy-cpp）
2. 在 APP 中填写服务器 IP、端口、密钥
3. 点击「连接」→ 授权 VPN 权限
4. 查看日志确认连接成功

### 本地自测模式

1. 切换到「本地自测」模式
2. 点击「启动本地服务」（内置服务端启动，端口 8443）
3. 点击「连接」（自动连接本机服务端）→ 授权 VPN 权限
4. 打开浏览器访问任意网站测试完整链路
5. 查看日志确认 Session 打开/关闭/数据转发正常
6. 测试完成后「断开」→「停止本地服务」

## 项目结构

```
app/src/main/java/com/dchen/kcpvpn/
├── core/                  # 核心层（纯 Java，无 Android 依赖）
│   ├── kcp/               # KCP 协议实现（Kcp.java ~1600行，从 C ikcp.c 移植）
│   ├── crypto/            # 加密（HKDF + AES-GCM + Nonce + 重放保护）
│   ├── protocol/          # SOCKS5 协议编解码 + 地址解析
│   └── session/           # KcpClientSession 客户端会话管理
├── vpn/                   # VPN 层
│   ├── KcpVpnService      # Android VpnService（前台通知 + VPN 接口生命周期）
│   ├── TunnelManager      # 隧道管理（连接/断开/指数退避重连）
│   └── PacketRouter       # IP 数据包路由（TCP 连接多路复用到 KCP 隧道）
├── server/                # 内置服务端（本地自测）
│   ├── LocalKcpServer     # 本地 KCP 服务端（UDP 监听 + 会话管理）
│   ├── ServerSession      # 服务端会话（背压控制：KCP 队列 >512 暂停 TCP 读取）
│   ├── Socks5Handler      # SOCKS5 连接处理
│   └── ServerConnectionManager  # TCP 转发连接池
├── ui/                    # Material Design 3 界面
│   ├── MainActivity       # 主界面 Activity
│   ├── MainFragment       # 配置输入 + 连接控制 + 状态显示
│   ├── LogFragment        # 实时日志列表（RecyclerView）
│   └── MainViewModel      # ViewModel（连接状态 + 流量统计 LiveData）
├── log/                   # 日志系统
│   ├── Logger             # 分级日志管理器（Application.onCreate 初始化）
│   ├── LogWriter          # 双文件循环存储（5MB × 2 = 10MB）
│   └── LogBuffer          # 内存缓冲（500 条）
└── util/                  # 工具类（ByteUtils, NetworkUtil, ServiceUtil）
```

## 数据流

```
出站（Phone → Internet）:
  VPN Interface → PacketRouter → SOCKS5 编码 → KcpClientSession → Crypto.encrypt → UDP Socket

入站（Internet → Phone）:
  UDP Socket → Crypto.decrypt → KCP.input() → KCP.recv() → PacketRouter → VPN Interface
```

## 协议参数

| 参数 | 值 | 说明 |
|------|-----|------|
| KCP_INTERVAL | 10ms | KCP 更新间隔 |
| KCP_SNDWND | 256 | 发送窗口 |
| KCP_RCVWND | 512 | 接收窗口 |
| KCP_MTU | 1400 | 最大传输单元 |
| KCP_TIMEOUT | 60s | 会话超时 |
| KCP nodelay | enabled / fastresend=5 / nocwnd=1 | 快速重传，禁用拥塞控制 |
| Default conv | 1 | 默认会话号 |
| APP_SALT | `kcp-proxy-hkdf-salt-v1` | 应用固定盐值 |
| HKDF info C2S | `kcp-proxy/c2s/v1` | 客户端→服务端密钥派生标签 |
| HKDF info S2C | `kcp-proxy/s2c/v1` | 服务端→客户端密钥派生标签 |
| NONCE_SIZE | 12 字节 | Nonce 长度 |
| TAG_SIZE | 16 字节 | GCM 认证标签 |
| AES_KEY_SIZE | 16 字节 | AES-128 密钥 |
| Nonce 方向 | CLIENT=0x01, SERVER=0x02 | 防止方向混淆 |
| Nonce 格式 | counter(8B) + direction(1B) + padding(3B) | 大端序 |
| REPLAY_WINDOW | 64 bit | 重放防护窗口 |
| Max counter | 2^48 | IND-CPA 安全上限 |

## 加密流程

```
密钥派生:
  user_key + user_salt + APP_SALT → HKDF-SHA256 → AES-128 密钥（按方向独立派生）

加密输出:
  [nonce(12字节)] + [ciphertext] + [tag(16字节)]

Nonce 格式:
  [counter(8字节, big-endian)] + [direction(1字节)] + [padding(3字节, 零)]
```

## 技术栈

- Java 8（无 Kotlin，无 Java 9+ API）
- AndroidX + Material Design 3
- Android VpnService API
- 无第三方代理内核

## 参考项目

- [kcp-proxy-cpp](../../kcp-proxy-cpp) — C++ 版本服务端（协议兼容目标）
- [skywind3000/kcp](https://github.com/skywind3000/kcp) — KCP 协议原版（C 语言）
