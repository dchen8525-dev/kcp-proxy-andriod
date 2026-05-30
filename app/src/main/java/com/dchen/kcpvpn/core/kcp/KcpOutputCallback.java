package com.dchen.kcpvpn.core.kcp;

/**
 * KCP 输出回调接口
 * 当 KCP 需要发送 UDP 数据包时调用此接口
 */
public interface KcpOutputCallback {
    /**
     * 输出 KCP 数据包
     * @param data 待发送的数据（已封装为 KCP 数据段）
     * @param len 数据长度
     */
    void onOutput(byte[] data, int len);
}