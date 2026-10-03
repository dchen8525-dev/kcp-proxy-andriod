package com.dchen.kcpvpn.vpn;

import com.dchen.kcpvpn.core.protocol.KcpFrame;
import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.Random;
import java.util.TreeMap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * 动态对抗测试：以"应用收到的字节流 == 服务器发送的字节流（严格有序、无重复、
 * 无缺失）"为不变量，轰炸 PacketRouter 的窗口流控 + 重传状态机。
 *
 * 模型：路由器写给 TUN 的每个包进入 toApp 队列；"应用"逐包消费——数据段按序
 * 拼接、乱序段缓存并回 3 个 dup-ACK、重复段重 ACK；ACK 携带按周期收窄/放开的
 * 通告窗口（驱动滞留与冲刷路径）；确定性随机丢包模拟 TUN 写丢失，重传必须把
 * 流修复完整。全部状态转移在测试线程同步驱动，固定种子下结果可复现。
 */
public class PacketRouterStreamIntegrityTest {
    private static final byte[] CLIENT_IP = {10, 0, 2, 15};
    private static final byte[] SERVER_IP = {(byte) 93, (byte) 184, (byte) 216, 34};
    private static final int CLIENT_PORT = 41020;
    private static final int SERVER_PORT = 443;
    private static final int SEGMENT_SIZE = VpnConfig.VPN_MTU - 40;
    private static int DROP_PERCENT = 20;
    /** heavy-loss 测试临时覆盖丢包率（测试线程内串行使用，无需同步）。 */
    private static int DROP_PERCENT_OVERRIDE = 0;
    private static final int MAX_STEPS = 500_000;

    private final Queue<byte[]> toApp = new ArrayDeque<>();
    private final List<KcpFrame> frames = new ArrayList<>();

    private PacketRouter router;
    private long connectionId;
    private int serverInitialSeq;
    private int clientIsn;

    // ---- 应用侧状态 ----
    private int nextExpectedSeq;
    private int totalEndSeq;
    private final java.io.ByteArrayOutputStream delivered = new java.io.ByteArrayOutputStream();
    private final TreeMap<Integer, byte[]> beyond = new TreeMap<>();
    private int ackWindowWalk;
    private final Random rng = new Random(0x5EED1234L);
    /** true：只丢尾段（驱动清理线程的停滞重传探测）；false：按 DROP_PERCENT 随机丢。 */
    private boolean dropTailOnly;
    private boolean tailDropUsed;
    /** true：乱序到达不回 dup-ACK（模拟 dup-ACK 全丢），修复只能靠 stall-probe。 */
    private boolean suppressDupAcks;

    // ---- 注入的载荷 ----
    private byte[] fullPayload;

    @Before
    public void setUp() {
        router = new PacketRouter();
        router.setLocalMode(true);
        router.start();
    }

    /** 建立连接并把 totalBytes 的载荷按 16KB DATA 帧全部注入路由器。 */
    private void injectTransfer(int isn, int totalBytes, long dropSeed) {
        rng.setSeed(dropSeed);
        clientIsn = isn;
        tailDropUsed = false;
        suppressDupAcks = false;
        sendFromApp(0x02, 0, 0, new byte[0], 65535);
        connectionId = frames.get(frames.size() - 1).getConnectionId();

        fullPayload = new byte[totalBytes];
        new Random(totalBytes).nextBytes(fullPayload);
        int offset = 0;
        while (offset < totalBytes) {
            int len = Math.min(16000, totalBytes - offset);
            router.handleInboundFrame(new KcpFrame(KcpFrame.TYPE_DATA, connectionId,
                    Arrays.copyOfRange(fullPayload, offset, offset + len)), toApp::add);
            offset += len;
        }
    }

    /**
     * 处理 toApp 队列直至清空。队列清空但流未交付完时，发 4 个窗口全开的重复
     * ACK——第 3 个触发快速重传（这正是应用读走缓冲后内核补发窗口更新 + 重复
     * ACK 的真实形态），直到流完整或重开预算耗尽。
     */
    private void drainToApp(int reopenBudget) {
        int steps = 0;
        while (true) {
            while (!toApp.isEmpty()) {
                if (++steps > MAX_STEPS) {
                    throw new AssertionError("drain loop did not quiesce (livelock?)");
                }
                appConsume(toApp.poll());
            }
            if (nextExpectedSeq == totalEndSeq) {
                return;
            }
            if (reopenBudget <= 0) {
                return; // 调用方决定是否视为失败
            }
            reopenBudget--;
            for (int i = 0; i < 4; i++) {
                sendFromApp(0x10, 0, nextExpectedSeq, new byte[0], 65535);
            }
        }
    }

    /** 应用模型消费一个 TUN 包。 */
    private void appConsume(byte[] pkt) {
        int flags = flags(pkt);
        if (flags == 0x12) { // SYN-ACK：锚定服务器 ISN，完成握手
            serverInitialSeq = seqNumber(pkt);
            nextExpectedSeq = serverInitialSeq + 1;
            totalEndSeq = serverInitialSeq + 1 + fullPayload.length;
            sendFromApp(0x10, clientIsn + 1, nextExpectedSeq, new byte[0], 65535);
            return;
        }
        if ((flags & 0x18) != 0x18) {
            return; // 纯 ACK / FIN / RST：应用模型无需响应
        }
        int seq = seqNumber(pkt);
        byte[] payload = payloadOf(pkt);
        boolean finalSegment = seq + payload.length == totalEndSeq;
        // 丢包模式：尾段只丢首次到达（真实内核会交付重传包，模型必须同样交付，
        // 否则 stall-probe 的每次重传都会被吞掉、探测永远无法修复）；随机模式
        // 按概率丢非尾段。
        int rate = DROP_PERCENT_OVERRIDE > 0 ? DROP_PERCENT_OVERRIDE : DROP_PERCENT;
        if (dropTailOnly && finalSegment) {
            if (!tailDropUsed) {
                tailDropUsed = true;
                return; // 首次到达丢弃
            }
            // 重传：照常交付（fall through 到下方按序拼接）
        } else if (rng.nextInt(100) < rate && !finalSegment) {
            return;
        }
        if (seq == nextExpectedSeq) {
            delivered.write(payload, 0, payload.length);
            nextExpectedSeq += payload.length;
            drainBeyond();
            sendAckWithWalk();
        } else if (seqAfter(seq, nextExpectedSeq)) {
            beyond.put(seq, payload);
            if (!suppressDupAcks) {
                for (int i = 0; i < 3; i++) {
                    sendAckWithWalk(); // 3 个 dup-ACK 触发快速重传
                }
            }
        } else {
            sendAckWithWalk(); // 重复段：重 ACK 当前位置
        }
    }

    private void drainBeyond() {
        byte[] seg;
        while ((seg = beyond.remove(nextExpectedSeq)) != null) {
            delivered.write(seg, 0, seg.length);
            nextExpectedSeq += seg.length;
        }
    }

    /** ACK 窗口按 8 个一周期收窄到 2000 再放开，覆盖滞留与冲刷两条路径。 */
    private void sendAckWithWalk() {
        int window = (ackWindowWalk % 8 == 5) ? 2000 : 65535;
        ackWindowWalk++;
        sendFromApp(0x10, 0, nextExpectedSeq, new byte[0], window);
    }

    @Test
    public void streamIntegrityUnderRandomLossAndWindowChurn() {
        injectTransfer(600_000, 96 * 1024, 0x5EEDABCDL);
        drainToApp(64);

        assertEquals("交付字节数必须与注入字节数一致",
                fullPayload.length, delivered.size());
        assertArrayEquals("交付字节流必须与注入字节流逐字节一致",
                fullPayload, delivered.toByteArray());
    }

    @Test
    public void streamIntegrityWithNarrowWindowPhase() {
        // 首个 ACK 就进入窄窗口相位（2000 < 一个段），强制走滞留 + 冲刷
        injectTransfer(700_000, 48 * 1024, 0x5EED777L);
        ackWindowWalk = 5;
        drainToApp(64);

        assertEquals(fullPayload.length, delivered.size());
        assertArrayEquals(fullPayload, delivered.toByteArray());
    }

    @Test
    public void streamIntegrityWithHeavyLossDifferentSeed() {
        // 更狠的种子：35% 丢包率 + 不同注入尺寸，换一批交错序列
        injectTransfer(800_000, 64 * 1024, 0x5EED9999L);
        DROP_PERCENT_OVERRIDE = 35;
        try {
            drainToApp(64);
        } finally {
            DROP_PERCENT_OVERRIDE = 0;
        }

        assertEquals(fullPayload.length, delivered.size());
        assertArrayEquals(fullPayload, delivered.toByteArray());
    }

    /**
     * 尾段丢失：应用侧无从察觉（没有后续段触发 dup-ACK），唯一修复途径是
     * 清理线程的停滞重传探测（3s 无 ACK 进展 + 1s 清扫节奏）。该测试是
     * probe 路径的唯一覆盖，用真实时钟等待其触发。
     */
    @Test
    public void tailLossIsRepairedByStallProbe() throws Exception {
        injectTransfer(900_000, 16 * 1024, 0x5EEDC0DEL);
        dropTailOnly = true;
        drainToApp(0); // 不发重开 ACK：把修复完全交给 stall-probe
        assertTrue("预热后尾段应尚未送达（丢包注入生效）",
                nextExpectedSeq != totalEndSeq);

        // 清理线程 1s 节奏 + 3s 停滞阈值；探测按整窗重传，一轮即覆盖全部
        // 未确认段。本用例注入 16KB（约 12 段、20% 概率随机丢 + 尾段）。
        long deadline = System.currentTimeMillis() + 30_000;
        while (nextExpectedSeq != totalEndSeq && System.currentTimeMillis() < deadline) {
            Thread.sleep(250);
            drainToApp(0);
        }

        assertEquals("stall-probe 必须修复尾段丢失", totalEndSeq, nextExpectedSeq);
        assertArrayEquals(fullPayload, delivered.toByteArray());
    }

    @Test
    public void multiHoleLossRepairedBySingleStallProbe() throws Exception {
        // dup-ACK 全丢（对端静默）：乱序段全部滞留在应用侧，快速重传没有触发
        // 信号——整窗探测重传成为唯一修复途径。一次探测应把窗口内的全部丢失
        // 段一轮补齐，而不是每 3 秒爬一段。
        injectTransfer(1_100_000, 24 * 1024, 0x5EED555L);
        suppressDupAcks = true;
        DROP_PERCENT_OVERRIDE = 25;
        try {
            drainToApp(0);
            assertTrue("预热后应有未交付缺口", nextExpectedSeq != totalEndSeq);

            long deadline = System.currentTimeMillis() + 30_000;
            while (nextExpectedSeq != totalEndSeq
                    && System.currentTimeMillis() < deadline) {
                Thread.sleep(250);
                drainToApp(0);
            }
        } finally {
            DROP_PERCENT_OVERRIDE = 0;
        }

        assertEquals("一次整窗探测必须修复全部缺口", totalEndSeq, nextExpectedSeq);
        assertArrayEquals(fullPayload, delivered.toByteArray());
    }

    // ---- harness ----

    private void sendFromApp(int flags, int seq, int ack, byte[] payload, int window) {
        int totalLen = 40 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(CLIENT_IP);
        buf.put(SERVER_IP);
        buf.putShort((short) CLIENT_PORT);
        buf.putShort((short) SERVER_PORT);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put((byte) flags);
        buf.putShort((short) window);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        router.handleOutboundPacket(buf.array(), frames::add, toApp::add);
    }

    private static int flags(byte[] packet) {
        return packet[33] & 0xFF;
    }

    private static int seqNumber(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(24);
    }

    private static byte[] payloadOf(byte[] packet) {
        return Arrays.copyOfRange(packet, 40, packet.length);
    }

    /** 32 位序号回绕安全比较：a 是否严格在 b 之后。 */
    private static boolean seqAfter(int a, int b) {
        return a != b && (a - b) > 0;
    }
}
