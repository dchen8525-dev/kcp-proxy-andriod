package com.dchen.kcpvpn.core.session;

/**
 * Session 状态枚举
 */
public enum SessionState {
    CREATED,        // 新创建
    CONNECTING,     // 正在连接
    ACTIVE,         // 正常工作
    CLOSING,        // 正在关闭
    CLOSED          // 已关闭
}