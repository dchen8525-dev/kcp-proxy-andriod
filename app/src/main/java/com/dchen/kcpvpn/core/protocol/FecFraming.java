package com.dchen.kcpvpn.core.protocol;

/**
 * FEC 帧探测 - 与 C++ kcp_tunnel.hpp looks_like_fec_frame 同逻辑。
 *
 * <p>C++ 端（0.3.0+）在启用 --fec 时，AEAD 明文 = FEC 头(6B) + 长度(2B) + KCP 报文，
 * FEC 头的 type 字段（小端 16 位，位于明文字节 4..5）取 0xf1..0xf3；而裸 KCP 段的
 * 字节 4 是命令字节（0x51..0x54）。两个值域不相交，所以裸段永远不会被误判成帧。
 *
 * <p>安卓端从不发送 FEC 帧：C++ 服务端按会话自适应封帧（首包是裸段则会话双向
 * 都保持裸格式），正常互操作不会在安卓侧见到帧。本探针只在 kcp.input 拒绝报文
 * 时用于给出与 C++ 相同措辞的明确诊断——它意味着对端 FEC 配置与本端不匹配
 * （例如把 C++ 客户端 --fec 指向了安卓端），而不是密钥/协议损坏。
 */
public final class FecFraming {

    private FecFraming() {
    }

    /**
     * 解密后的明文是否是 FEC 封帧（C++ kTypeData/kTypeParity/kTypeOob）。
     *
     * @param plaintext AEAD 解密后的完整明文（salt/nonce 在线格式里位于 AEAD 之外，
     *                  因此明文字节 0 就是 FEC 头的起点）
     */
    public static boolean looksLikeFecFrame(byte[] plaintext, int length) {
        if (plaintext == null || length < 8) {
            return false;
        }
        int type = (plaintext[4] & 0xFF) | ((plaintext[5] & 0xFF) << 8);
        return type == 0xF1 || type == 0xF2 || type == 0xF3;
    }
}
