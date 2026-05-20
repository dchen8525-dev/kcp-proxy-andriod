package com.example.kcpvpn.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.example.kcpvpn.R;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;
import com.example.kcpvpn.ui.MainActivity;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * KCP VPN 服务 - Android VpnService 实现
 * 全局流量捕获并转发到 KCP 隧道
 */
public class KcpVpnService extends VpnService {

    private ParcelFileDescriptor vpnInterface;
    private FileInputStream vpnInputStream;
    private FileOutputStream vpnOutputStream;
    private FileChannel vpnInputChannel;
    private FileChannel vpnOutputChannel;

    private TunnelManager tunnelManager;
    private PacketRouter packetRouter;

    private Thread vpnReadThread;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile VpnConnectionState connectionState;

    // 配置参数
    private String serverHost;
    private int serverPort;
    private String key;
    private boolean localMode;

    private static final String PREFS_NAME = "kcp_vpn_prefs";
    private static final String KEY_SERVER_HOST = "server_host";
    private static final String KEY_SERVER_PORT = "server_port";
    private static final String KEY_KEY = "key";
    private static final String KEY_LOCAL_MODE = "local_mode";

    // 流量统计 — AtomicLong 保证原子性
    private final AtomicLong uploadBytes = new AtomicLong(0);
    private final AtomicLong downloadBytes = new AtomicLong(0);

    // 连接时长
    private volatile long connectionStartTime;

    @Override
    public void onCreate() {
        super.onCreate();
        // Logger已在Application中初始化
        Logger.info(LogConfig.MODULE_VPN, "VpnService created");

        connectionState = VpnConnectionState.DISCONNECTED;
        uploadBytes.set(0);
        downloadBytes.set(0);

        // 恢复上次保存的参数（进程死亡后重启）
        restoreParams();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Logger.info(LogConfig.MODULE_VPN, "onStartCommand called");

        if (intent != null) {
            serverHost = intent.getStringExtra("server_host");
            serverPort = intent.getIntExtra("server_port", 0);
            key = intent.getStringExtra("key");
            localMode = intent.getBooleanExtra("local_mode", false);

            // 持久化参数，供进程死亡后恢复
            saveParams();

            Logger.info(LogConfig.MODULE_VPN, "Parameters: host=" + serverHost
                    + ", port=" + serverPort + ", localMode=" + localMode);
        } else {
            Logger.warning(LogConfig.MODULE_VPN, "onStartCommand intent is null, using saved params");
            // START_STICKY 重启：使用已保存的参数
            restoreParams();
            if (serverHost == null) {
                Logger.error(LogConfig.MODULE_VPN, "No saved parameters, cannot restart VPN");
                stopSelf();
                return START_NOT_STICKY;
            }
        }

        // 立即启动前台服务（Android 11+ 要求）
        startForegroundService();

        if (running.compareAndSet(false, true)) {
            Logger.info(LogConfig.MODULE_VPN, "Starting VPN on background thread...");
            // 在后台线程执行网络 I/O，避免主线程 ANR
            Thread startThread = new Thread(this::startVpn, "VPN-Start");
            startThread.start();
        } else {
            Logger.info(LogConfig.MODULE_VPN, "VPN already running");
        }

        return START_STICKY;
    }

    /**
     * 启动前台服务
     */
    private void startForegroundService() {
        createNotificationChannel();

        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent,
                PendingIntent.FLAG_IMMUTABLE);

        Notification notification = createNotification(pendingIntent);

        startForeground(VpnConfig.NOTIFICATION_ID, notification);
        Logger.info(LogConfig.MODULE_VPN, "Foreground service started");
    }

    /**
     * 创建通知渠道 — 使用 IMPORTANCE_LOW 避免 VPN 运行时响铃
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    VpnConfig.NOTIFICATION_CHANNEL_ID,
                    VpnConfig.NOTIFICATION_CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_LOW);

            channel.setDescription("KCP VPN 服务状态");
            channel.setShowBadge(false);

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    /**
     * 创建通知
     */
    private Notification createNotification(PendingIntent pendingIntent) {
        Notification.Builder builder;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, VpnConfig.NOTIFICATION_CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        builder.setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle("KCP VPN")
                .setContentText(connectionState.getDisplayText())
                .setContentIntent(pendingIntent)
                .setOngoing(true);

        return builder.build();
    }

    /**
     * 更新通知
     */
    private void updateNotification() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            Intent notificationIntent = new Intent(this, MainActivity.class);
            PendingIntent pendingIntent = PendingIntent.getActivity(
                    this, 0, notificationIntent,
                    PendingIntent.FLAG_IMMUTABLE);

            String content = connectionState.getDisplayText();
            if (connectionState == VpnConnectionState.CONNECTED) {
                long duration = getConnectionDuration();
                String upload = formatBytes(uploadBytes.get());
                String download = formatBytes(downloadBytes.get());
                content = "已连接 " + duration + "秒 | ↑" + upload + " ↓" + download;
            }

            Notification.Builder builder;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                builder = new Notification.Builder(this, VpnConfig.NOTIFICATION_CHANNEL_ID);
            } else {
                builder = new Notification.Builder(this);
            }

            builder.setSmallIcon(R.drawable.ic_vpn)
                    .setContentTitle("KCP VPN")
                    .setContentText(content)
                    .setContentIntent(pendingIntent)
                    .setOngoing(true);

            manager.notify(VpnConfig.NOTIFICATION_ID, builder.build());
        }
    }

    /**
     * 启动 VPN
     */
    private void startVpn() {
        Logger.info(LogConfig.MODULE_VPN, "startVpn() begin");

        connectionState = VpnConnectionState.CONNECTING;
        broadcastState();
        updateNotification();

        try {
            Logger.info(LogConfig.MODULE_VPN, "Building VPN interface...");

            // 建立 VPN 接口
            Builder builder = new Builder();
            builder.setSession(VpnConfig.VPN_SESSION_NAME)
                    .setMtu(VpnConfig.VPN_MTU)
                    .addAddress(VpnConfig.VPN_ADDRESS, VpnConfig.VPN_ADDRESS_PREFIX)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("8.8.4.4")
                    .addDisallowedApplication(getPackageName());  // 排除自身，避免流量循环

            vpnInterface = builder.establish();

            if (vpnInterface == null) {
                Logger.error(LogConfig.MODULE_VPN, "VPN interface establish failed - vpnInterface is null");
                connectionState = VpnConnectionState.DISCONNECTED;
                broadcastState();
                updateNotification();
                stopSelf();
                return;
            }

            Logger.info(LogConfig.MODULE_VPN, "VPN interface established, fd=" + vpnInterface.getFd());

            // 保持 FileInputStream/FileOutputStream 引用以便正确关闭
            vpnInputStream = new FileInputStream(vpnInterface.getFileDescriptor());
            vpnOutputStream = new FileOutputStream(vpnInterface.getFileDescriptor());
            vpnInputChannel = vpnInputStream.getChannel();
            vpnOutputChannel = vpnOutputStream.getChannel();

            Logger.info(LogConfig.MODULE_VPN, "VPN channels created");

            // 创建隧道管理器
            Logger.info(LogConfig.MODULE_VPN, "Creating TunnelManager: " + serverHost + ":" + serverPort);
            tunnelManager = new TunnelManager(serverHost, serverPort, key);
            tunnelManager.setStateCallback(state -> {
                Logger.info(LogConfig.MODULE_VPN, "Tunnel state changed: " + state.getDisplayText());
                connectionState = state;
                broadcastState();
                updateNotification();
            });
            tunnelManager.setDataReceivedCallback(data -> {
                handleInboundData(data);
            });

            // 创建数据包路由器
            Logger.info(LogConfig.MODULE_VPN, "Creating PacketRouter");
            packetRouter = new PacketRouter();
            packetRouter.start();

            // 连接隧道
            Logger.info(LogConfig.MODULE_VPN, "Connecting tunnel...");
            if (!tunnelManager.connect()) {
                Logger.error(LogConfig.MODULE_VPN, "Tunnel connect failed");
                closeVpn();
                connectionState = VpnConnectionState.DISCONNECTED;
                broadcastState();
                updateNotification();
                stopSelf();
                return;
            }

            Logger.info(LogConfig.MODULE_VPN, "Tunnel connected successfully");

            // 启动读取线程
            startVpnReadThread();

            connectionStartTime = System.currentTimeMillis();

            // 不重复设 CONNECTED，tunnelManager 的回调已经设过了
            Logger.info(LogConfig.MODULE_VPN, "VPN started successfully");

        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Start VPN error: " + e.getMessage());
            closeVpn();
            connectionState = VpnConnectionState.DISCONNECTED;
            broadcastState();  // 修复：异常路径也广播状态
            updateNotification();
            stopSelf();
        }
    }

    /**
     * 启动 VPN 读取线程
     */
    private void startVpnReadThread() {
        vpnReadThread = new Thread(() -> {
            ByteBuffer buffer = ByteBuffer.allocate(VpnConfig.VPN_MTU + 28);

            while (running.get() && vpnInputChannel != null) {
                try {
                    buffer.clear();
                    int len = vpnInputChannel.read(buffer);

                    if (len > 0) {
                        buffer.flip();
                        byte[] packet = new byte[len];
                        buffer.get(packet);

                        // 处理出站数据包
                        packetRouter.handleOutboundPacket(packet,
                                new PacketRouter.OutboundCallback() {
                                    @Override
                                    public void onSendToKcp(byte[] data) {
                                        tunnelManager.sendData(data);
                                        uploadBytes.addAndGet(data.length);
                                    }

                                    @Override
                                    public void onWriteToVpn(byte[] responsePacket) {
                                        try {
                                            ByteBuffer outBuf = ByteBuffer.wrap(responsePacket);
                                            vpnOutputChannel.write(outBuf);
                                        } catch (IOException e) {
                                            Logger.error(LogConfig.MODULE_VPN, "VPN write-back error: " + e.getMessage());
                                        }
                                    }
                                });

                        Logger.debug(LogConfig.MODULE_VPN, "VPN read: " + len + " bytes");
                    }

                } catch (IOException e) {
                    if (running.get()) {
                        Logger.error(LogConfig.MODULE_VPN, "VPN read error: " + e.getMessage());
                    }
                    break;
                }
            }
        }, "VPN-Read");
        vpnReadThread.start();
    }

    /**
     * 处理入站数据
     */
    private void handleInboundData(byte[] data) {
        if (!running.get() || vpnOutputChannel == null) {
            return;
        }

        packetRouter.handleInboundData(data,
                new PacketRouter.WritePacketCallback() {
                    @Override
                    public void onWritePacket(byte[] packet) {
                        try {
                            ByteBuffer buffer = ByteBuffer.wrap(packet);
                            vpnOutputChannel.write(buffer);
                            downloadBytes.addAndGet(packet.length);

                            Logger.debug(LogConfig.MODULE_VPN, "VPN write: " + packet.length + " bytes");
                        } catch (IOException e) {
                            Logger.error(LogConfig.MODULE_VPN, "VPN write error: " + e.getMessage());
                        }
                    }
                });
    }

    /**
     * 关闭 VPN
     */
    private void closeVpn() {
        running.set(false);

        Logger.info(LogConfig.MODULE_VPN, "Closing VPN...");

        // 停止隧道
        if (tunnelManager != null) {
            tunnelManager.disconnect();
            tunnelManager = null;
        }

        // 停止路由器
        if (packetRouter != null) {
            packetRouter.stop();
            packetRouter = null;
        }

        // 先关闭 VPN 接口，解除 vpnReadThread 的阻塞读
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
            }
            if (vpnInputStream != null) {
                vpnInputStream.close();
            }
            if (vpnOutputStream != null) {
                vpnOutputStream.close();
            }
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_VPN, "Close VPN interface error: " + e.getMessage());
        }

        // 等待读取线程终止
        if (vpnReadThread != null) {
            vpnReadThread.interrupt();
            try {
                vpnReadThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            vpnReadThread = null;
        }

        vpnInputStream = null;
        vpnOutputStream = null;
        vpnInputChannel = null;
        vpnOutputChannel = null;
        vpnInterface = null;

        // 清除保存的参数
        clearSavedParams();

        Logger.info(LogConfig.MODULE_VPN, "VPN closed");
    }

    @Override
    public void onDestroy() {
        closeVpn();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Logger.warning(LogConfig.MODULE_VPN, "VPN authorization revoked");
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        stopForeground(true);  // 移除通知
        stopSelf();
    }

    /**
     * 停止 VPN（供外部调用）
     */
    public void stopVpn() {
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        updateNotification();
        stopSelf();
    }

    /**
     * 获取连接状态
     */
    public VpnConnectionState getConnectionState() {
        return connectionState;
    }

    /**
     * 获取连接时长（秒）
     */
    public long getConnectionDuration() {
        if (!running.get()) {
            return 0;
        }
        return (System.currentTimeMillis() - connectionStartTime) / 1000;
    }

    /**
     * 获取上传流量
     */
    public long getUploadBytes() {
        return uploadBytes.get();
    }

    /**
     * 获取下载流量
     */
    public long getDownloadBytes() {
        return downloadBytes.get();
    }

    /**
     * 格式化字节
     */
    private String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        } else if (bytes < 1024 * 1024) {
            return (bytes / 1024) + "KB";
        } else {
            return (bytes / (1024 * 1024)) + "MB";
        }
    }

    /**
     * 保存参数到 SharedPreferences
     */
    private void saveParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
                .putString(KEY_SERVER_HOST, serverHost)
                .putInt(KEY_SERVER_PORT, serverPort)
                .putString(KEY_KEY, key)
                .putBoolean(KEY_LOCAL_MODE, localMode)
                .apply();
    }

    /**
     * 从 SharedPreferences 恢复参数
     */
    private void restoreParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        serverHost = prefs.getString(KEY_SERVER_HOST, null);
        serverPort = prefs.getInt(KEY_SERVER_PORT, 0);
        key = prefs.getString(KEY_KEY, null);
        localMode = prefs.getBoolean(KEY_LOCAL_MODE, false);
    }

    /**
     * 清除保存的参数
     */
    private void clearSavedParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().clear().apply();
        serverHost = null;
        serverPort = 0;
        key = null;
        localMode = false;
    }

    /**
     * 广播状态变化
     */
    private void broadcastState() {
        Logger.info(LogConfig.MODULE_VPN, "Broadcasting state: " + connectionState.getDisplayText());

        Intent intent = new Intent(VpnStateBroadcast.ACTION_STATE_CHANGED);
        intent.putExtra(VpnStateBroadcast.EXTRA_STATE, connectionState.name());
        intent.putExtra(VpnStateBroadcast.EXTRA_UPLOAD_BYTES, uploadBytes.get());
        intent.putExtra(VpnStateBroadcast.EXTRA_DOWNLOAD_BYTES, downloadBytes.get());
        intent.putExtra(VpnStateBroadcast.EXTRA_DURATION, getConnectionDuration());

        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }
}