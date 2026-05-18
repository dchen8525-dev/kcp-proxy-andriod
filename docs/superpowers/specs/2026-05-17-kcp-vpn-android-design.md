---
name: kcp-vpn-android-design
description: Android KCP 全局 VPN 应用完整设计规范，与 C++ kcp-proxy-cpp 服务端兼容
---

# Android KCP VPN 应用设计规范

## 项目概述

开发一款适配 Android 11（API 30）及以上系统的全局 KCP 隧道 VPN 应用。基于原生 VpnService 实现全局流量代理，自研 Java KCP 客户端，与现有 C++ kcp-proxy-cpp 服务端完全兼容。

### 核心特性

- 双模式运行：外网模式（连接远程服务器）+ 本地自测模式（内置 KCP 服务端）
- 纯 Java 实现，不依赖第三方代理内核
- 与 C++ kcp-proxy-cpp 服务端协议完全兼容
- Material Design 3 UI
- 完整分级日志系统
- Android 11+ 前台服务与后台限制合规处理

### 技术决策摘要

| 决策项 | 选择 |
|-------|------|
| KCP 实现 | 基于开源 Java KCP 库适配，移植 skywind3000/kcp |
| 加密方案 | 与 C++ 项目一致：HKDF-SHA256 + AES-128-GCM + 重放保护 |
| 本地自测模式 | SOCKS5 代理模式（完整链路测试） |
| UI 风格 | Material Design 3 |
| 日志存储 | 固定大小循环存储（10MB） |
| 重连策略 | 指数退避重连（1s→2s→4s...→60s） |
| 连接状态持久化 | 不持久化，每次手动连接 |
| 架构方案 | 分层架构（Core / VPN / Server / UI / Log） |

---

## 第一章：核心层设计（Core Layer）

核心层是纯 Java 实现，不依赖 Android SDK，与 C++ kcp-proxy-cpp 服务端协议完全兼容。

### 1.1 KCP 协议实现

移植 C++ 项目使用的 [skywind3000/kcp](https://github.com/skywind3000/kcp) 库：

```
core/kcp/
├── Kcp.java              # 主类（移植 ikcp.c）
├── KcpConfig.java        # 配置常量
├── Segment.java          # KCP 数据段
├── AckList.java          # ACK 列表
└── KcpOutputCallback.java# 输出回调接口
```

**关键配置（与 C++ config.hpp 一致）**：

| 参数 | 值 | 说明 |
|-----|---|------|
| INTERVAL_MS | 10 | KCP 更新间隔 |
| SNDWND | 256 | 发送窗口 |
| RCVWND | 512 | 接收窗口 |
| MTU | 1400 | 最大传输单元 |
| conv | 1 | 默认会话号 |
| nodelay | (1, 10, 5, 1) | 快速模式参数 |

### 1.2 加密实现（与 C++ crypto.cpp 完全一致）

```
core/crypto/
├── Crypto.java           # 主加密类
├── HkdfSha256.java       # HKDF-SHA256 密钥派生
├── AesGcmCipher.java     # AES-128-GCM 加密
├── ReplayWindow.java     # 重放攻击防护（64位滑动窗口）
├── NonceGenerator.java   # Nonce 生成
├── CryptoConfig.java     # 常量配置
```

**加密格式**：

```
密钥派生：
  input: user_key + user_salt + APP_SALT("kcp-proxy-hkdf-salt-v1")
  info: "kcp-proxy/c2s/v1" (encrypt) 或 "kcp-proxy/s2c/v1" (decrypt)
  output: AES-128 密钥 (16字节)

加密输出格式：
  [nonce(12字节)] + [ciphertext] + [tag(16字节)]

Nonce格式：
  [counter(8字节, big-endian)] + [direction(1字节)]
  direction: CLIENT=0x01, SERVER=0x02
```

**常量配置（CryptoConfig.java）**：

| 常量 | 值 | 说明 |
|-----|---|------|
| NONCE_SIZE | 12 | Nonce 长度 |
| TAG_SIZE | 16 | GCM 认证标签长度 |
| AES_KEY_SIZE | 16 | AES-128 密钥长度 |
| REPLAY_WINDOW_BITS | 64 | 重放窗口位数 |
| MAX_COUNTER | 2^48 | 计数器上限 |
| NONCE_DIR_CLIENT | 0x01 | 客户端方向标识 |
| NONCE_DIR_SERVER | 0x02 | 服务端方向标识 |
| APP_SALT | "kcp-proxy-hkdf-salt-v1" | 应用级固定盐值 |

### 1.3 SOCKS5 协议（与 C++ socks5.cpp/address.cpp 一致）

```
core/protocol/
├── Socks5.java           # SOCKS5 常量和结构
├── Socks5Request.java    # 请求构建
├── Socks5Response.java   # 响应解析
├── AddressEncoder.java   # 地址编码（IPv4/Domain/IPv6）
└── AddressParser.java    # 地址解析
```

**SOCKS5 Request 格式**：

```
[VER(0x05)] + [CMD(0x01=CONNECT)] + [RSV(0x00)] + [ATYP] + [ADDR] + [PORT(2字节)]
```

**地址编码格式**：

| 类型 | ATYP | 格式 |
|-----|------|------|
| IPv4 | 0x01 | `[ATYP] + [4字节IP] + [2字节PORT]` |
| Domain | 0x03 | `[ATYP] + [1字节长度] + [domain] + [2字节PORT]` |
| IPv6 | 0x04 | `[ATYP] + [16字节IP] + [2字节PORT]` |

**SOCKS5 响应码**：

| 响应 | 值 | 说明 |
|-----|---|------|
| SUCCEEDED | 0x00 | 成功 |
| GENERAL_FAILURE | 0x01 | 一般失败 |
| NETWORK_UNREACHABLE | 0x03 | 网络不可达 |
| HOST_UNREACHABLE | 0x04 | 主机不可达 |
| CONNECTION_REFUSED | 0x05 | 连接被拒绝 |
| COMMAND_NOT_SUPPORTED | 0x07 | 命令不支持 |
| ADDRESS_TYPE_NOT_SUPPORTED | 0x08 | 地址类型不支持 |

### 1.4 Session 管理（与 C++ KCPClientSession 一致）

```
core/session/
├── KcpClientSession.java # KCP 客户端会话（核心类）
├── SessionState.java     # 状态枚举
└── SessionConfig.java    # Session 配置
```

**KcpClientSession 关键方法**：

| 方法 | 说明 |
|-----|------|
| `connect()` | 创建 UDP socket，启动 KCP update 定时器，启动 UDP 接收循环 |
| `sendData(byte[])` | 通过 KCP 发送数据（先加密） |
| `asyncReadSome()` | 异步读取 KCP 接收的数据 |
| `close()` | 关闭会话，释放资源 |
| `markHandshakeDone()` | 标记 SOCKS5 握手完成 |

**内部数据流**：

```
出站：应用数据 → KCP.send() → outputCallback → Crypto.encrypt() → UDP 发送
入站：UDP 接收 → Crypto.decrypt() → KCP.input() → 应用层读取
```

---

## 第二章：VPN 层设计

VPN 层负责 Android 系统级 VPN 功能实现，将全局流量捕获并转发到 KCP 隧道。

### 2.1 VpnService 实现

```
vpn/
├── KcpVpnService.java    # Android VpnService 实现
├── VpnConfig.java        # VPN 配置（路由、MTU 等）
├── TunnelManager.java    # 隧道管理（KCP 连接生命周期）
├── PacketRouter.java     # 数据包路由（VPN → KCP → VPN）
└── VpnConnectionState.java # 连接状态枚举
```

**VPN 接口配置**：

```java
Builder builder = new Builder()
    .setSession("KCP VPN")
    .setMtu(1400)                      // 与 KCP MTU 一致
    .addAddress("10.0.0.2", 32)        // VPN 内部地址
    .addRoute("0.0.0.0", 0)            // 捕获所有 IPv4
    .addRoute "::", 0)                 // 捕获所有 IPv6
    .setBlocking(true);                // 阻塞模式
```

### 2.2 数据包处理流程

**出站流程（手机 → 外网）**：

```
APP 发送数据 → VPN 接口捕获 → PacketRouter.readPacket()
→ 解析目标地址 → SOCKS5 Request 封装 → 
KcpClientSession.sendData() → KCP 加密封装 → UDP 发送到服务端
```

**入站流程（外网 → 手机）**：

```
服务端 UDP 响应 → KcpClientSession 接收解密 → KCP 输出数据
→ SOCKS5 Response / 数据 → PacketRouter.writePacket() → 
VPN 接口返回给 APP
```

### 2.3 连接状态管理

**VpnConnectionState 状态**：

| 状态 | 说明 |
|-----|------|
| DISCONNECTED | 未连接 |
| CONNECTING | 正在建立 VPN 和 KCP 连接 |
| CONNECTED | 正常工作 |
| RECONNECTING | 网络异常，正在重连 |
| DISCONNECTING | 正在断开 |

**指数退避重连参数**：

| 参数 | 值 |
|-----|---|
| 初始间隔 | 1 秒 |
| 最大间隔 | 60 秒 |
| 退避因子 | 2（1→2→4→8→16→32→60） |
| 达到最大后 | 保持 60 秒间隔持续重试 |

### 2.4 前台服务配置

**通知配置**：

- 通知渠道：VPN 服务（高优先级）
- 通知内容：连接状态、时长、上下行流量
- 通知 ID：固定（1001），服务运行期间持续显示

---

## 第三章：内置服务端设计

内置服务端用于本地自测模式，实现完整的 KCP 服务端 + SOCKS5 代理。

### 3.1 服务端架构

```
server/
├── LocalKcpServer.java       # 本地 KCP 服务端主类
├── ServerSession.java        # 服务端会话
├── Socks5Handler.java        # SOCKS5 协议处理
├── ServerConfig.java         # 服务端配置
├── ServerConnectionManager.java # TCP 连接管理
└── ServerCleanupTimer.java   # 会话清理定时器
```

### 3.2 新连接处理流程

```
UDP 收到数据包 → 尝试解密认证 → 成功则创建 ServerSession
→ 否则丢弃（防止未认证攻击者占用资源）
→ Session 启动后等待 SOCKS5 Request
→ 解析目标地址 → 建立 TCP 连接到目标 → 
→ 开始双向数据转发
```

### 3.3 数据转发

| 方向 | 流程 |
|-----|------|
| KCP → TCP | 从 KCP 读取数据，写入目标服务器 TCP socket |
| TCP → KCP | 从目标服务器读取，通过 KCP 发送回客户端 |

**背压控制**：

- 当 KCP 发送队列超过 `KCP_SNDWND * 2 = 512` 时暂停 TCP 读取
- 等待 KCP 队列降低后继续读取

### 3.4 超时参数

| 参数 | 值 | 说明 |
|-----|---|------|
| KCP_TIMEOUT_SEC | 60 | 会话超时时间 |
| CONNECT_TIMEOUT_SEC | 15 | TCP 连接超时 |
| cleanup_interval | 30秒 | 清理检查间隔 |
| MAX_CONCURRENT_SESSIONS | 4096 | 最大并发会话数 |

---

## 第四章：UI 层设计（Material Design 3）

### 4.1 Activity 与 Fragment 结构

```
ui/
├── MainActivity.java           # 主 Activity
├── MainFragment.java           # 主界面（配置 + 连接控制）
├── LogFragment.java            # 日志显示界面
├── MainViewModel.java          # 状态管理
├── ConnectionRepository.java   # 连接状态数据源
└── adapters/
│   └── LogAdapter.java         # 日志列表适配器
```

### 4.2 主界面布局

**MainFragment 区域**：

1. **模式选择区**：Segmented Button（外网模式 / 本地自测模式）
2. **配置输入区**：Server IP、Port、Key（外网模式）
3. **本地自测区**：端口显示、启动/停止本地服务按钮（本地模式）
4. **连接控制区**：连接/断开按钮、状态指示器
5. **状态显示区**：时长、上行/下行流量、延迟
6. **日志入口**：底部 Tab 或按钮切换

### 4.3 日志界面布局

**LogFragment 区域**：

1. **日志过滤区**：下拉菜单（All / Debug / Info / Warning / Error）
2. **日志列表**：RecyclerView，时间戳 + 级别标签 + 内容
3. **操作按钮**：一键清空日志

**日志级别颜色**：

| 级别 | 颜色 |
|-----|------|
| Debug | 灰色 |
| Info | 蓝色 |
| Warning | 橙色 |
| Error | 红色 |

### 4.4 Material 3 组件

| 组件 | 用途 |
|-----|------|
| MaterialButton | 连接/断开按钮 |
| MaterialTextInputLayout | 配置输入框 |
| MaterialSegmentedButton | 模式切换 |
| MaterialCardView | 各区域容器 |
| Chip | 状态标签 |

---

## 第五章：日志系统设计

### 5.1 日志架构

```
log/
├── Logger.java             # 日志管理器
├── LogLevel.java           # 日志级别枚举
├── LogEntry.java           # 日志条目结构
├── LogWriter.java          # 文件写入器（循环存储）
├── LogBuffer.java          # 内存缓冲区（实时显示）
└── LogConfig.java          # 日志配置常量
```

### 5.2 日志级别

| 级别 | 值 | 说明 |
|-----|---|------|
| DEBUG | 0 | 调试日志（KCP 收发、加密细节） |
| INFO | 1 | 普通信息（连接状态、Session 创建/关闭） |
| WARNING | 2 | 警告（重连尝试、认证失败） |
| ERROR | 3 | 错误（异常、连接失败） |

### 5.3 模块标识

| 模块 | 标识 |
|-----|------|
| VPN 服务 | vpn |
| KCP 客户端 | kcp_client |
| KCP 服务端 | kcp_server |
| 加密 | crypto |
| SOCKS5 | socks5 |
| UI | ui |
| 重连 | reconnect |

### 5.4 文件持久化

**存储策略**：

- 双文件交替：kcpvpn_part1.log / kcpvpn_part2.log
- 单文件上限：5MB
- 总容量：10MB
- 超出时切换文件并清空旧文件

### 5.5 日志格式

```
[时间戳] [级别] [模块] 内容

示例：
2026-05-17 14:30:15.123 [INFO] [kcp_client] Connected to server 192.168.1.100:8443
2026-05-17 14:30:15.456 [DEBUG] [crypto] Encrypt: 140 bytes -> 168 bytes
2026-05-17 14:31:00.789 [WARNING] [reconnect] Connection lost, retrying in 4s (attempt 3)
```

---

## 第六章：Android 11+ 适配设计

### 6.1 VPN 权限处理

**授权流程**：

```
1. VpnService.prepare(context) 获取 Intent
2. 若 Intent ≠ null → 启动系统授权 Activity → 用户确认
3. 若 Intent == null → 已有授权，直接启动 VPN
```

### 6.2 前台服务配置

**Manifest 配置**：

```xml
<service
    android:name=".vpn.KcpVpnService"
    android:foregroundServiceType="dataSync"
    android:exported="false" />

<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
```

**启动要求**：

- 服务启动后 5 秒内调用 `startForeground()`
- 持续显示通知直到服务停止

### 6.3 后台保活策略

| 策略 | 说明 |
|-----|------|
| 前台服务 | VPN 作为前台服务，系统优先级最高 |
| 不依赖后台 | VpnService 断开即停止，不尝试后台恢复 |
| 用户重开 | 用户重新打开 APP 时检查状态并提示 |

### 6.4 生命周期管理

**VpnService 生命周期**：

| 回调 | 操作 |
|-----|------|
| onCreate() | 初始化资源 |
| onStartCommand() | startForeground() + 启动连接 |
| onDestroy() | 停止 KCP + 关闭 VPN + 清理资源 |
| onRevoke() | 用户撤销授权 → 立即停止服务 |

### 6.5 流量统计

- VPN 层内部统计：每次读写累加计数
- 无需依赖系统 NetworkStatsManager API

---

## 项目文件结构总览

```
app/
├── java/com.example.kcpvpn/
│   ├── core/              # 核心层（纯 Java）
│   │   ├── kcp/           # KCP 协议
│   │   ├── crypto/        # 加密（HKDF + AES-GCM）
│   │   ├── protocol/      # SOCKS5 协议
│   │   └── session/       # 会话管理
│   ├── vpn/               # VPN 层（Android 特定）
│   │   ├── KcpVpnService
│   │   ├── TunnelManager
│   │   ├── PacketRouter
│   │   └── VpnConfig
│   ├── server/            # 内置服务端
│   │   ├── LocalKcpServer
│   │   ├── ServerSession
│   │   ├── Socks5Handler
│   │   └── ServerConfig
│   ├── ui/                # UI 层（Material 3）
│   │   ├── MainActivity
│   │   ├── MainFragment
│   │   ├── LogFragment
│   │   ├── MainViewModel
│   │   └── adapters/
│   ├── log/               # 日志系统
│   │   ├── Logger
│   │   ├── LogWriter
│   │   └── LogBuffer
│   └── util/              # Android 工具
│       └── ServiceUtil
│       └── NetworkUtil
│       └ ByteUtils
```

---

## 兼容性说明

本设计与 C++ kcp-proxy-cpp 项目完全兼容：

| 兼容项 | 说明 |
|-------|------|
| 加密协议 | HKDF-SHA256 + AES-128-GCM，Nonce 格式、密钥派生完全一致 |
| KCP 配置 | MTU、窗口、nodelay 参数一致 |
| SOCKS5 | Request/Response 格式、地址编码一致 |
| Session | conv=1，状态管理逻辑一致 |
| 服务端认证 | 首包认证 + 重放保护一致 |

---

## 附录：本地自测流程使用教程

### 外网模式使用

1. 启动远程 KCP 服务端（kcp-proxy-cpp）
2. 在 APP 中填写服务端 IP、端口、密钥
3. 点击"连接"按钮
4. VPN 授权后开始全局代理
5. 查看日志确认连接成功

### 本地自测模式使用

1. 切换到"本地自测模式"
2. 点击"启动本地服务"（APP 内置服务端启动）
3. 点击"连接"按钮（自动连接本机服务端）
4. VPN 授权后开始本机闭环测试
5. 可打开浏览器访问任意网站测试完整链路
6. 查看日志确认 Session 打开/关闭/数据转发正常
7. 测试完成后点击"断开"停止 VPN
8. 点击"停止本地服务"关闭内置服务端

---

## 附录：常见问题排查

| 问题 | 可能原因 | 排查方向 |
|-----|---------|---------|
| 连接失败 | 密钥不匹配 | 检查密钥是否与服务端一致 |
| 连接失败 | 服务端未启动 | 确认服务端已运行且端口正确 |
| 无流量转发 | VPN 授权未完成 | 检查系统授权对话框是否弹出 |
| 连接中断 | 网络切换 | 查看重连日志，确认指数退避生效 |
| 本地测试失败 | 端口被占用 | 更换本地服务端口 |
| 认证失败 | 加密配置不一致 | 检查盐值、密钥派生参数 |