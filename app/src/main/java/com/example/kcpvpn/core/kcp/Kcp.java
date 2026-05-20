package com.example.kcpvpn.core.kcp;

import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedList;

/**
 * KCP 协议核心实现 - 移植自 skywind3000/kcp ikcp.c
 * 与 C++ kcp_wrapper.cpp 对应
 * 所有多字节字段使用 LITTLE-ENDIAN（与 ikcp.c 一致）
 */
public class Kcp {
    // KCP 常量
    private static final int IKCP_RTO_NDL = 30;    // nodelay 模式最小 RTO
    private static final int IKCP_RTO_DEF = 200;    // 默认 RTO
    private static final int IKCP_RTO_MIN = 100;    // 最小 RTO
    private static final int IKCP_THRESH_INIT = 2;   // 慢启动初始阈值
    private static final int IKCP_THRESH_MIN = 2;    // 最小阈值
    private static final int IKCP_DEADLINK = 20;     // 死链判定（与 C 一致）
    private static final int IKCP_FASTACK_LIMIT = 5; // 快速重传次数限制（与 ikcp.h 一致）

    // KCP 状态
    private int conv;
    private int mtu;
    private int mss;
    private int state;
    private int snd_una;
    private int snd_nxt;
    private int rcv_nxt;
    private int ssthresh;
    private int rx_rttval;
    private int rx_srtt;
    private int rx_rto;
    private int rx_minrto;
    private int snd_wnd;
    private int rcv_wnd;
    private int rmt_wnd;
    private int cwnd;
    private int probe;
    private int interval;
    private int ts_flush;
    private int nodelay;
    private int updated;
    private int ts_probe;
    private int probe_wait;
    private int dead_link;
    private int incr;
    private boolean nocwnd;      // 是否禁用拥塞控制
    private int fastresend;     // 快速重传阈值（由 setNodelay 的 resend 参数设置）
    private boolean stream;     // stream 模式（暂不实现）

    // 发送队列和接收队列
    private LinkedList<Segment> snd_queue = new LinkedList<>();
    private LinkedList<Segment> rcv_queue = new LinkedList<>();
    private LinkedList<Segment> snd_buf = new LinkedList<>();
    private LinkedList<Segment> rcv_buf = new LinkedList<>();

    // ACK 列表（需要发送给对端的 ACK）
    private AckList ackList = new AckList();

    // 输出回调
    private KcpOutputCallback outputCallback;

    // 当前时间
    private int current;

    public Kcp(int conv) {
        this.conv = conv;
        this.mtu = KcpConfig.KCP_MTU;
        this.mss = this.mtu - Segment.HEADER_SIZE;
        this.state = 0;
        this.snd_una = 0;
        this.snd_nxt = 0;
        this.rcv_nxt = 0;
        this.ssthresh = IKCP_THRESH_INIT;
        this.rx_rttval = 0;
        this.rx_srtt = 0;
        this.rx_rto = IKCP_RTO_DEF;
        this.rx_minrto = IKCP_RTO_NDL;
        this.snd_wnd = KcpConfig.KCP_SNDWND;
        this.rcv_wnd = KcpConfig.KCP_RCVWND;
        this.rmt_wnd = KcpConfig.KCP_RCVWND;
        this.cwnd = 0;
        this.probe = 0;
        this.interval = KcpConfig.KCP_INTERVAL_MS;
        this.ts_flush = 0;
        this.nodelay = 0;
        this.updated = 0;
        this.ts_probe = 0;
        this.probe_wait = 0;
        this.dead_link = IKCP_DEADLINK;
        this.incr = 0;
        this.nocwnd = false;
        this.fastresend = 0;
        this.current = 0;

        Logger.debug("kcp", "KCP created: conv=" + conv);
    }

    /**
     * 有符号差值比较（用于 32-bit 序列号 wraparound）
     * 与 ikcp.c 的 _itimediff 一致
     */
    private static int timeDiff(int a, int b) {
        return a - b;
    }

    public void setOutputCallback(KcpOutputCallback callback) {
        this.outputCallback = callback;
    }

    /**
     * 设置 nodelay 参数 - 与 ikcp.c ikcp_nodelay 一致
     * resend 参数映射到 fastresend（快速重传阈值），不是 rx_minrto
     */
    public void setNodelay(int nodelay, int interval, int resend, int nocwnd) {
        this.nodelay = nodelay;
        if (nodelay != 0) {
            this.rx_minrto = IKCP_RTO_NDL;    // nodelay 模式下 rx_minrto = 30ms
            this.fastresend = resend;           // resend 映射到 fastresend
        } else {
            this.rx_minrto = IKCP_RTO_DEF;     // 非nodelay 模式 rx_minrto = 200ms
            this.fastresend = 0;
        }

        if (interval >= 0) {
            this.interval = Math.max(interval, 1);
        }

        // nocwnd: 当 >= 0 时设置 nocwnd 标志
        if (nocwnd >= 0) {
            this.nocwnd = (nocwnd != 0);
        }
        // 当 nocwnd=0（启用拥塞控制）时设置 ssthresh
        if (!this.nocwnd) {
            this.ssthresh = this.rmt_wnd > 0 ? this.rmt_wnd : this.rcv_wnd;
        }

        Logger.debug("kcp", "setNodelay: nodelay=" + nodelay + ", interval=" + this.interval
                + ", fastresend=" + this.fastresend + ", nocwnd=" + this.nocwnd);
    }

    /**
     * 设置窗口大小
     */
    public void setWndSize(int sndwnd, int rcvwnd) {
        if (sndwnd > 0) {
            this.snd_wnd = sndwnd;
        }
        if (rcvwnd > 0) {
            this.rcv_wnd = Math.max(rcvwnd, 128);  // ikcp.c 保证最小 128
        }
    }

    /**
     * 设置 MTU
     */
    public void setMtu(int mtu) {
        if (mtu < 50 || mtu < Segment.HEADER_SIZE) {
            return;
        }
        this.mtu = mtu;
        this.mss = this.mtu - Segment.HEADER_SIZE;
        Logger.debug("kcp", "setMtu: mtu=" + mtu);
    }

    /**
     * 发送数据 - 返回实际接受的字节数
     */
    public int send(byte[] data) {
        return send(data, 0, data.length);
    }

    public int send(byte[] data, int offset, int len) {
        if (len == 0) {
            return -1;
        }

        // 计算分片数量（限制不超过接收窗口）
        int count = (len + mss - 1) / mss;
        if (count == 0) count = 1;
        if (count > this.rcv_wnd) {
            // 超过远端接收窗口，丢弃
            return -2;
        }

        // 创建分片
        int sent = 0;
        for (int i = 0; i < count; i++) {
            int segLen = Math.min(mss, len - sent);
            Segment seg = new Segment(segLen);
            seg.conv = conv;
            seg.cmd = Segment.IKCP_CMD_PUSH;
            seg.frg = (count - i - 1);
            seg.len = segLen;
            System.arraycopy(data, offset + sent, seg.data, 0, segLen);
            snd_queue.add(seg);
            sent += segLen;
        }

        return len;  // 返回接受的字节数
    }

    /**
     * 接收数据 - 正确实现 fastRecover 和 moveRcvData
     */
    public int recv(byte[] buffer) {
        if (rcv_queue.isEmpty()) {
            return -1;
        }

        int peekSize = peekSize();
        if (peekSize < 0) {
            return -2;
        }

        if (peekSize > buffer.length) {
            return -3;
        }

        boolean fastRecover = false;
        // C 的 ikcp_recv: recover = (nrcv_que >= rcv_wnd)，表示接收队列满了
        if (rcv_queue.size() >= rcv_wnd) {
            fastRecover = true;
        }

        int received = 0;
        while (!rcv_queue.isEmpty()) {
            Segment seg = rcv_queue.pollFirst();
            System.arraycopy(seg.data, 0, buffer, received, seg.len);
            received += seg.len;

            if (seg.frg == 0) {
                break;
            }
        }

        // fast recover: 通知对端窗口已打开
        if (fastRecover) {
            probe |= 2;  // IKCP_ASK_TELL
        }

        // 从 rcv_buf 移动新数据到 rcv_queue
        moveRcvData();

        // 更新接收窗口
        int newWnd = rcv_wnd - rcv_queue.size();
        if (newWnd > 0) {
            // 告知对端有空余窗口
        }

        return received;
    }

    /**
     * 获取接收队列中可读数据大小
     */
    public int peekSize() {
        if (rcv_queue.isEmpty()) {
            return -1;
        }

        Segment seg = rcv_queue.peekFirst();
        if (seg.frg == 0) {
            return seg.len;
        }

        int totalLen = 0;
        for (Segment s : rcv_queue) {
            totalLen += s.len;
            if (s.frg == 0) {
                return totalLen;
            }
        }

        return -1;
    }

    /**
     * 输入接收到的数据 - 正确处理 ACK（增长 cwnd）和 fastack
     */
    public int input(byte[] data) {
        return input(data, 0, data.length);
    }

    public int input(byte[] data, int offset, int len) {
        if (len < Segment.HEADER_SIZE) {
            return -1;
        }

        long oldSndUna = snd_una;
        int maxack = 0;
        int latestTs = 0;

        ByteBuffer buf = ByteBuffer.wrap(data, offset, len);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        while (buf.remaining() >= Segment.HEADER_SIZE) {
            int conv = buf.getInt();
            byte cmd = buf.get();
            int frg = buf.get() & 0xFF;
            int wnd = buf.getShort() & 0xFFFF;
            int ts = buf.getInt();
            int sn = buf.getInt();
            int una = buf.getInt();
            int segLen = buf.getInt();

            if (conv != this.conv) {
                return -1;
            }

            if (segLen < 0 || buf.remaining() < segLen) {
                return -2;
            }

            // 更新远端窗口
            rmt_wnd = wnd;

            // 处理 una — 移除已确认的段
            parseUna(una);
            shrinkSndBuf();

            switch (cmd) {
                case Segment.IKCP_CMD_ACK:
                    // 处理 ACK — 更新 RTT, fastack, cwnd
                    if (timeDiff(current, ts) >= 0) {
                        updateRtt(timeDiff(current, ts));
                    }
                    handleAck(sn);
                    shrinkSndBuf();
                    // 跟踪最大 ACK 用于批量 fastack
                    if (timeDiff(sn, maxack) > 0) {
                        maxack = sn;
                        latestTs = ts;
                    }
                    break;

                case Segment.IKCP_CMD_PUSH:
                    handlePush(sn, ts, frg, wnd, buf, segLen);
                    break;

                case Segment.IKCP_CMD_WASK:
                    probe |= 2;  // IKCP_ASK_TELL: 响应窗口探测
                    break;

                case Segment.IKCP_CMD_WINS:
                    break;

                default:
                    return -3;
            }

            if (buf.remaining() < Segment.HEADER_SIZE) {
                break;
            }
        }

        // 批量 fastack：使用最大 ACK 号一次性处理
        if (maxack > 0) {
            parseFastAck(maxack);
        }

        // cwnd 增长逻辑（与 ikcp.c ikcp_input 一致）
        if (timeDiff(snd_una, (int) oldSndUna) > 0) {
            // 有段被确认，增长拥塞窗口
            if (cwnd < rmt_wnd) {
                if (cwnd < ssthresh) {
                    // 慢启动：每确认一个段，cwnd 加 1（指数增长）
                    cwnd++;
                    incr += mss;
                } else {
                    // 拥塞避免：每 MSS/cwnd 个段确认，cwnd 加 1
                    if (incr < mss) incr = mss;
                    incr += (mss * mss) / incr + (mss / 16);
                    if ((cwnd + 1) * mss <= incr) {
                        cwnd = (incr + mss - 1) / ((mss > 0) ? mss : 1);
                    }
                }
                if (cwnd > rmt_wnd) {
                    cwnd = rmt_wnd;
                    incr = rmt_wnd * mss;
                }
            }
        }

        updated = 1;
        return 0;
    }

    /**
     * 处理 ACK — 与 ikcp.c ikcp_parse_ack 一致
     * 从 snd_buf 中移除已确认的段（而不是仅标记）
     */
    private void handleAck(int sn) {
        if (timeDiff(sn, snd_una) < 0 || timeDiff(sn, snd_nxt) >= 0) {
            return;
        }

        // 从 snd_buf 找到并移除该段
        for (int i = 0; i < snd_buf.size(); i++) {
            Segment seg = snd_buf.get(i);
            if (seg.sn == sn) {
                snd_buf.remove(i);
                break;
            }
            if (timeDiff(seg.sn, sn) > 0) {
                break;  // 后面的 sn 更大，不可能找到
            }
        }
    }

    /**
     * 更新 fastack — 对已确认段之前的未确认段增加 fastack
     */
    private void parseFastAck(int sn) {
        if (timeDiff(sn, snd_una) < 0 || timeDiff(sn, snd_nxt) >= 0) {
            return;
        }

        for (Segment seg : snd_buf) {
            if (timeDiff(sn, seg.sn) < 0) {
                break;
            }
            if (timeDiff(seg.sn, snd_una) >= 0) {
                seg.fastack++;
            }
        }
    }

    /**
     * 更新 RTT — 与 ikcp.c ikcp_update_ack 一致
     */
    private void updateRtt(int rtt) {
        if (rx_srtt == 0) {
            rx_srtt = rtt;
            rx_rttval = rtt / 2;
        } else {
            int delta = timeDiff(rtt, rx_srtt);
            rx_srtt += delta / 8;
            rx_rttval += (Math.abs(delta) - rx_rttval) / 4;
        }

        int rto = rx_srtt + Math.max(interval, rx_rttval * 4);
        rx_rto = Math.max(rx_minrto, Math.min(rto, 6000));
    }

    /**
     * 处理 una — 移除 sn < una 的段
     */
    private void parseUna(int una) {
        while (!snd_buf.isEmpty()) {
            Segment seg = snd_buf.peekFirst();
            if (timeDiff(una, seg.sn) > 0) {
                snd_buf.pollFirst();
            } else {
                break;
            }
        }
    }

    /**
     * 收缩发送缓冲区 — 更新 snd_una
     */
    private void shrinkSndBuf() {
        if (!snd_buf.isEmpty()) {
            snd_una = snd_buf.peekFirst().sn;
        } else {
            snd_una = snd_nxt;
        }
    }

    /**
     * 处理 PUSH 数据
     */
    private void handlePush(int sn, int ts, int frg, int wnd, ByteBuffer buf, int segLen) {
        // 更新远端窗口
        rmt_wnd = wnd;

        // 添加到 ACK 列表（需要发回给对端）
        ackList.add(sn, ts);

        // 检查序列号是否在接收窗口内
        if (timeDiff(sn, rcv_nxt + rcv_wnd) >= 0 || timeDiff(sn, rcv_nxt) < 0) {
            // 超出窗口，但仍然发 ACK
            return;
        }

        // 创建段
        Segment seg = new Segment(segLen);
        seg.conv = conv;
        seg.cmd = Segment.IKCP_CMD_PUSH;
        seg.frg = frg;
        seg.ts = ts;
        seg.sn = sn;
        seg.len = segLen;
        if (segLen > 0) {
            buf.get(seg.data, 0, segLen);
        }

        // 放入接收缓冲区
        insertRcvBuf(seg);
    }

    /**
     * 插入段到接收缓冲区（反向扫描优化）
     */
    private void insertRcvBuf(Segment newSeg) {
        // 检查是否已存在
        for (Segment seg : rcv_buf) {
            if (seg.sn == newSeg.sn) {
                return;
            }
        }

        // 反向扫描插入（大多数新段 sn 较大）
        boolean inserted = false;
        for (int i = rcv_buf.size() - 1; i >= 0; i--) {
            if (timeDiff(newSeg.sn, rcv_buf.get(i).sn) > 0) {
                rcv_buf.add(i + 1, newSeg);
                inserted = true;
                break;
            }
        }
        if (!inserted) {
            rcv_buf.add(0, newSeg);
        }

        // 移动到接收队列
        moveRcvData();
    }

    /**
     * 将接收缓冲区的数据移动到接收队列
     */
    private void moveRcvData() {
        while (!rcv_buf.isEmpty()) {
            Segment seg = rcv_buf.peekFirst();
            if (seg.sn == rcv_nxt && rcv_queue.size() < rcv_wnd) {
                rcv_buf.pollFirst();
                rcv_queue.add(seg);
                rcv_nxt++;
            } else {
                break;
            }
        }
    }

    /**
     * 更新 KCP — 与 ikcp.c ikcp_update 一致
     * 只在合适的时间调用 flush
     */
    public void update(int currentMs) {
        this.current = currentMs;

        if (updated == 0) {
            ts_flush = current;
        }

        updated = 1;

        int slap = timeDiff(current, ts_flush);

        // 处理时钟跳跃
        if (slap >= 10000 || slap < -10000) {
            ts_flush = current;
            slap = 0;
        }

        if (slap >= 0) {
            ts_flush += interval;
            if (timeDiff(current, ts_flush) >= 0) {
                ts_flush = current + interval;
            }
            flush();
        }

        // 窗口探测
        if (rmt_wnd == 0) {
            if (probe_wait == 0) {
                probe_wait = 2000;  // 2 秒初始探测间隔
                ts_probe = current + probe_wait;
            } else if (timeDiff(current, ts_probe) >= 0) {
                if (probe_wait < 8000) {
                    probe_wait *= 2;  // 指数退避
                }
                ts_probe = current + probe_wait;
                probe |= 1;  // IKCP_ASK_SEND: 请求窗口探测
            }
        } else {
            probe_wait = 0;
            ts_probe = 0;
        }
    }

    /**
     * 刷新 — 与 ikcp.c ikcp_flush 一致
     */
    public void flush() {
        // 计算窗口大小
        int cwndSize = Math.min(rmt_wnd, snd_wnd);
        if (!nocwnd) {
            cwndSize = Math.min(cwndSize, cwnd);
        }
        if (cwndSize < 0) {
            cwndSize = 0;
        }

        int count = 0;
        boolean lost = false;
        boolean change = false;

        // 发送窗口探测
        if ((probe & 1) != 0) {
            sendProbe((byte) Segment.IKCP_CMD_WASK);
            probe &= ~1;
        }
        if ((probe & 2) != 0) {
            sendProbe((byte) Segment.IKCP_CMD_WINS);
            probe &= ~2;
        }

        // 发送 ACK（每个 ACK 一个独立段，与 ikcp.c 一致）
        for (int i = 0; i < ackList.size(); i++) {
            int sn = ackList.getSnList().get(i);
            int ts = ackList.getTsList().get(i);
            sendAck(sn, ts);
        }
        ackList.clear();

        // 计算 una（使用 rcv_nxt，不是 snd_una）
        int una = rcv_nxt;

        // 发送发送缓冲区中的数据（先处理超时重传和快速重传）
        for (Segment seg : snd_buf) {
            boolean needSend = false;
            boolean needResend = false;

            if (seg.xmit == 0) {
                // 首次发送
                needSend = true;
                seg.xmit = 1;
                seg.rto = rx_rto;
                seg.resendts = current + seg.rto;
            } else if (timeDiff(current, seg.resendts) >= 0) {
                // 超时重传
                needSend = true;
                needResend = true;
                if (nodelay == 0) {
                    seg.rto += Math.max(seg.rto, rx_rto);
                } else {
                    int step = (nodelay < 2) ? seg.rto : rx_rto;
                    seg.rto += step / 2;
                }
                seg.resendts = current + seg.rto;
                lost = true;
            } else if (seg.fastack >= fastresend && fastresend > 0) {
                // 快速重传
                if ((seg.xmit <= IKCP_FASTACK_LIMIT) || (IKCP_FASTACK_LIMIT <= 0)) {
                    needSend = true;
                    needResend = true;
                    seg.fastack = 0;
                    seg.resendts = current + seg.rto;
                    change = true;
                }
            }

            if (needSend) {
                if (seg.xmit >= dead_link) {
                    state = -1;  // 死链
                    return;
                }

                seg.xmit++;
                seg.ts = current;
                seg.wnd = rcv_queue.size() < rcv_wnd ? rcv_wnd - rcv_queue.size() : 0;
                seg.una = una;
                sendSegment(seg);
                count++;
            }
        }

        // 拥塞控制：超时重传时降低 ssthresh
        if (lost) {
            ssthresh = Math.max(cwnd / 2, IKCP_THRESH_MIN);
            cwnd = ssthresh;
            incr = cwnd * mss;
        }

        // 拥塞控制：快速重传时降低 ssthresh
        if (change) {
            ssthresh = Math.max(cwnd / 2, IKCP_THRESH_MIN);
            incr = ssthresh * mss;
            if (cwnd > ssthresh) {
                cwnd = ssthresh;
            }
        }

        // 发送发送队列中的新数据
        while (!snd_queue.isEmpty() && timeDiff(snd_nxt, snd_una + cwndSize) < 0) {
            Segment seg = snd_queue.pollFirst();
            seg.conv = conv;
            seg.cmd = Segment.IKCP_CMD_PUSH;
            seg.wnd = rcv_queue.size() < rcv_wnd ? rcv_wnd - rcv_queue.size() : 0;
            seg.ts = current;
            seg.sn = snd_nxt++;
            seg.una = una;
            seg.resendts = current + rx_rto;
            seg.rto = rx_rto;
            seg.xmit = 0;  // 首次发送，xmit=0（与 C++ 一致）
            seg.fastack = 0;
            snd_buf.add(seg);
            sendSegment(seg);
            count++;

            // 首次发送时增长 cwnd（慢启动）
            if (cwnd < rmt_wnd && cwnd < ssthresh) {
                cwnd++;
                incr += mss;
            } else if (cwnd >= ssthresh) {
                if (incr < mss) incr = mss;
                incr += (mss * mss) / incr + (mss / 16);
                if ((cwnd + 1) * mss <= incr) {
                    cwnd++;
                }
            }
        }

        if (count > 0) {
            Logger.debug("kcp", "flush: sent " + count + " segments");
        }
    }

    /**
     * 发送段
     */
    private void sendSegment(Segment seg) {
        if (outputCallback != null) {
            byte[] data = seg.encode();
            outputCallback.onOutput(data, data.length);
        }
    }

    /**
     * 发送探测包 — una 使用 rcv_nxt
     */
    private void sendProbe(byte cmd) {
        Segment seg = new Segment(0);
        seg.conv = conv;
        seg.cmd = cmd;
        seg.wnd = rcv_queue.size() < rcv_wnd ? rcv_wnd - rcv_queue.size() : 0;
        seg.ts = current;
        seg.sn = 0;
        seg.una = rcv_nxt;  // 使用 rcv_nxt，不是 snd_una
        seg.len = 0;

        sendSegment(seg);
    }

    /**
     * 发送 ACK — 每个 ACK 是独立的 24 字节 KCP 段（与 ikcp.c 一致）
     */
    private void sendAck(int sn, int ts) {
        Segment seg = new Segment(0);
        seg.conv = conv;
        seg.cmd = Segment.IKCP_CMD_ACK;
        seg.wnd = rcv_queue.size() < rcv_wnd ? rcv_wnd - rcv_queue.size() : 0;
        seg.ts = ts;      // ACK 段携带原始时间戳
        seg.sn = sn;      // ACK 段的 sn 是被确认的序列号
        seg.una = rcv_nxt; // 使用 rcv_nxt
        seg.len = 0;

        sendSegment(seg);
    }

    /**
     * 获取等待发送的数据大小
     */
    public int waitSend() {
        return snd_queue.size() + snd_buf.size();
    }

    /**
     * 检查连接是否存活
     */
    public boolean isAlive() {
        return state >= 0;
    }

    public int getMtu() { return mtu; }
    public int getMss() { return mss; }
    public int getSndWnd() { return snd_wnd; }
    public int getRcvWnd() { return rcv_wnd; }
    public int getConv() { return conv; }
}