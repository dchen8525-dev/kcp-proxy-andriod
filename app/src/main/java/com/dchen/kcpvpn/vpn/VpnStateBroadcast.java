package com.dchen.kcpvpn.vpn;

/**
 * VPN 状态广播 - 用于 VPN 服务向 UI 同步状态
 */
public class VpnStateBroadcast {
    public static final String ACTION_STATE_CHANGED = "com.dchen.kcpvpn.VPN_STATE_CHANGED";
    public static final String EXTRA_STATE = "state";
    public static final String EXTRA_UPLOAD_BYTES = "upload_bytes";
    public static final String EXTRA_DOWNLOAD_BYTES = "download_bytes";
    public static final String EXTRA_DURATION = "duration";
    public static final String EXTRA_ERROR = "error";
}