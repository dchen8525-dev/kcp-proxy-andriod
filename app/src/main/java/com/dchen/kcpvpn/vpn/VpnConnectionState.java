package com.dchen.kcpvpn.vpn;

/**
 * VPN 连接状态枚举
 */
public enum VpnConnectionState {
    DISCONNECTED,    // 未连接
    CONNECTING,      // 正在连接
    CONNECTED,       // 已连接
    RECONNECTING,    // 正在重连
    DISCONNECTING    // 正在断开

    ;

    /**
     * 获取状态显示文本
     */
    public String getDisplayText() {
        switch (this) {
            case DISCONNECTED:
                return "未连接";
            case CONNECTING:
                return "连接中...";
            case CONNECTED:
                return "已连接";
            case RECONNECTING:
                return "重连中...";
            case DISCONNECTING:
                return "断开中...";
            default:
                return "未知";
        }
    }
}