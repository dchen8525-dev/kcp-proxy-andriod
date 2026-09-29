package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.kcp.KcpConfig;

/**
 * VPN 配置
 */
public class VpnConfig {
    // VPN 接口配置
    public static final String VPN_SESSION_NAME = "KCP VPN";
    public static final String VPN_ADDRESS = "10.0.0.2";
    public static final int VPN_ADDRESS_PREFIX = 32;
    // 接口上的 IPv6 地址用 ULA：/128 前缀 + ::/0 路由，内核据此为出站 IPv6 选源地址。
    public static final String VPN_ADDRESS_IPV6 = "fd00::2";
    public static final int VPN_ADDRESS_PREFIX_IPV6 = 128;
    public static final int VPN_MTU = KcpConfig.KCP_MTU;

    // 前台服务通知
    public static final int NOTIFICATION_ID = 1001;
    public static final String NOTIFICATION_CHANNEL_ID = "kcpvpn_service";
    public static final String NOTIFICATION_CHANNEL_NAME = "VPN 服务";
}