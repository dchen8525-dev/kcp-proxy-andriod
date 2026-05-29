package com.example.kcpvpn.server;

import com.example.kcpvpn.core.crypto.Crypto;
import com.example.kcpvpn.core.kcp.Kcp;
import com.example.kcpvpn.core.kcp.KcpConfig;
import com.example.kcpvpn.core.kcp.KcpOutputCallback;
import com.example.kcpvpn.core.protocol.KcpFrame;
import com.example.kcpvpn.core.protocol.KcpFrameCodec;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 服务端 KCP 会话。
 */
public class ServerSession {

    private final String sessionId;
    private final InetSocketAddress clientAddr;
    private final Crypto crypto;
    private final Kcp kcp;
    private final Object kcpLock;
    private final KcpFrameCodec frameCodec;

    private volatile boolean running;
    private final AtomicLong lastActivityTime;

    private Consumer<byte[]> sendCallback;
    private Consumer<KcpFrame> frameHandler;

    private Thread updateThread;

    public ServerSession(InetSocketAddress clientAddr, Crypto crypto) {
        this.sessionId = clientAddr.getAddress().getHostAddress() + ":" + clientAddr.getPort();
        this.clientAddr = clientAddr;
        this.crypto = crypto;
        this.kcp = new Kcp(KcpConfig.DEFAULT_CONV);
        this.kcpLock = new Object();
        this.frameCodec = new KcpFrameCodec(LogConfig.MODULE_KCP_SERVER);

        this.running = false;
        this.lastActivityTime = new AtomicLong(System.currentTimeMillis());

        kcp.setNodelay(KcpConfig.NODELAY_ENABLED, KcpConfig.NODELAY_INTERVAL,
                KcpConfig.NODELAY_RESEND, KcpConfig.NODELAY_NOCWND);
        kcp.setWndSize(KcpConfig.KCP_SNDWND, KcpConfig.KCP_RCVWND);
        kcp.setMtu(KcpConfig.KCP_MTU);

        kcp.setOutputCallback(new KcpOutputCallback() {
            @Override
            public void onOutput(byte[] data, int len) {
                handleKcpOutput(data, len);
            }
        });

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession created: " + sessionId);
    }

    public void start() {
        running = true;
        touchActivity();
        startUpdateThread();
        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession started: " + sessionId);
    }

    private void startUpdateThread() {
        updateThread = new Thread(() -> {
            while (running) {
                try {
                    long nowMs = System.currentTimeMillis();
                    synchronized (kcpLock) {
                        kcp.update((int) (nowMs & 0xFFFFFFFFL));
                        kcp.flush();
                    }
                    Thread.sleep(KcpConfig.KCP_INTERVAL_MS);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "ServerKCP-Update-" + sessionId);
        updateThread.start();
    }

    public void receiveData(byte[] decryptedData) {
        if (!running) {
            return;
        }

        touchActivity();

        int ret;
        synchronized (kcpLock) {
            ret = kcp.input(decryptedData);
        }
        if (ret < 0) {
            Logger.warning(LogConfig.MODULE_KCP_SERVER, "ikcp_input rejected packet, ret=" + ret);
            return;
        }

        deliverFrames();
    }

    private void handleKcpOutput(byte[] data, int len) {
        if (!running || sendCallback == null) {
            return;
        }

        try {
            byte[] encrypted = crypto.encrypt(data);
            sendCallback.accept(encrypted);
            Logger.debug(LogConfig.MODULE_KCP_SERVER, "Output: " + data.length
                    + " plain -> " + encrypted.length + " encrypted");
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_KCP_SERVER, "Encrypt error: " + e.getMessage());
        }
    }

    public void sendFrame(KcpFrame frame) {
        if (!running) {
            return;
        }

        byte[] data = KcpFrameCodec.encode(frame);
        synchronized (kcpLock) {
            int ret = kcp.send(data);
            if (ret < 0) {
                Logger.error(LogConfig.MODULE_KCP_SERVER, "ikcp_send failed, ret=" + ret
                        + ", connectionId=" + frame.getConnectionId()
                        + ", frameType=" + KcpFrame.frameTypeName(frame.getFrameType())
                        + ", payloadLength=" + frame.getPayloadLength());
                return;
            }

            kcp.update((int) (System.currentTimeMillis() & 0xFFFFFFFFL));
            kcp.flush();
        }

        Logger.debug(LogConfig.MODULE_KCP_SERVER, "Sent frame: connectionId="
                + frame.getConnectionId() + ", frameType="
                + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                + frame.getPayloadLength());
    }

    private void deliverFrames() {
        Consumer<KcpFrame> handler = frameHandler;
        if (handler == null) {
            return;
        }

        while (true) {
            byte[] data;
            synchronized (kcpLock) {
                int peekSize = kcp.peekSize();
                if (peekSize <= 0) {
                    break;
                }

                byte[] buf = new byte[peekSize];
                int len = kcp.recv(buf);
                if (len <= 0) {
                    break;
                }

                data = new byte[len];
                System.arraycopy(buf, 0, data, 0, len);
            }

            List<KcpFrame> frames = frameCodec.decode(data);
            for (KcpFrame frame : frames) {
                Logger.debug(LogConfig.MODULE_KCP_SERVER, "Recv frame: connectionId="
                        + frame.getConnectionId() + ", frameType="
                        + KcpFrame.frameTypeName(frame.getFrameType()) + ", payloadLength="
                        + frame.getPayloadLength());
                handler.accept(frame);
            }
        }
    }

    public void setSendCallback(Consumer<byte[]> callback) {
        this.sendCallback = callback;
    }

    public void setFrameHandler(Consumer<KcpFrame> frameHandler) {
        this.frameHandler = frameHandler;
    }

    public boolean isAlive() {
        if (!running) {
            return false;
        }
        long age = System.currentTimeMillis() - lastActivityTime.get();
        return age < ServerConfig.KCP_TIMEOUT_MS;
    }

    public int waitSend() {
        synchronized (kcpLock) {
            return kcp.waitSend();
        }
    }

    private void touchActivity() {
        lastActivityTime.set(System.currentTimeMillis());
    }

    public void stop() {
        if (!running) {
            return;
        }
        running = false;

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession stopping: " + sessionId);

        if (updateThread != null) {
            updateThread.interrupt();
            updateThread = null;
        }

        Logger.info(LogConfig.MODULE_KCP_SERVER, "ServerSession stopped: " + sessionId);
    }

    public String getSessionId() {
        return sessionId;
    }

    public InetSocketAddress getClientAddr() {
        return clientAddr;
    }
}
