package com.example.kcpvpn.core.kcp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * KCP 数据段 - 移植自 skywind3000/kcp ikcp.h
 * 所有字段使用 LITTLE-ENDIAN 编码（与 C ikcp.c 一致）
 */
public class Segment {
    // 段头部长度
    public static final int HEADER_SIZE = 24;

    // 段类型标识
    public static final int IKCP_CMD_PUSH = 81;   // 数据推送
    public static final int IKCP_CMD_ACK = 82;     // 确认
    public static final int IKCP_CMD_WASK = 83;    // 窗口探测请求
    public static final int IKCP_CMD_WINS = 84;    // 窗口探测响应

    // 段字段
    public int conv;        // 会话号
    public byte cmd;        // 命令类型
    public int frg;         // 分片编号
    public int wnd;         // 可用窗口大小
    public int ts;          // 时间戳
    public int sn;          // 序列号
    public int una;         // 未确认序列号
    public int len;         // 数据长度

    // 重传控制
    public int xmit;        // 发送次数
    public int rto;         // 重传超时（per-segment）
    public int fastack;     // 快速确认计数
    public int resendts;   // 重传时间戳

    // 数据
    public byte[] data;

    public Segment(int size) {
        this.data = new byte[size];
        this.len = 0;
        this.xmit = 0;
        this.rto = 0;
        this.fastack = 0;
    }

    /**
     * 将段编码为字节数组（LITTLE-ENDIAN，与 ikcp.c 一致）
     */
    public byte[] encode() {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + len);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(conv);
        buf.put(cmd);
        buf.put((byte) frg);
        buf.putShort((short) wnd);
        buf.putInt(ts);
        buf.putInt(sn);
        buf.putInt(una);
        buf.putInt(len);
        if (len > 0 && data != null) {
            buf.put(data, 0, len);
        }
        return buf.array();
    }

    /**
     * 从字节缓冲区解码段头（LITTLE-ENDIAN）
     */
    public static Segment decode(ByteBuffer buf) {
        Segment seg = new Segment(0);
        seg.conv = buf.getInt();
        seg.cmd = buf.get();
        seg.frg = buf.get() & 0xFF;  // 无符号
        seg.wnd = buf.getShort() & 0xFFFF;
        seg.ts = buf.getInt();
        seg.sn = buf.getInt();
        seg.una = buf.getInt();
        seg.len = buf.getInt();
        return seg;
    }
}
