package com.example.kcpvpn.ui;

import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import android.app.Application;

import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;
import com.example.kcpvpn.server.LocalKcpServer;
import com.example.kcpvpn.server.ServerConfig;
import com.example.kcpvpn.util.ServiceUtil;
import com.example.kcpvpn.vpn.VpnConnectionState;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 主界面 ViewModel - 状态管理
 */
public class MainViewModel extends AndroidViewModel {

    public enum Mode {
        REMOTE,  // 外网模式
        LOCAL    // 本地自测模式
    }

    private final MutableLiveData<Mode> mode = new MutableLiveData<>(Mode.REMOTE);
    private final MutableLiveData<VpnConnectionState> connectionState = new MutableLiveData<>(VpnConnectionState.DISCONNECTED);
    private final MutableLiveData<Long> duration = new MutableLiveData<>(0L);
    private final MutableLiveData<Long> uploadBytes = new MutableLiveData<>(0L);
    private final MutableLiveData<Long> downloadBytes = new MutableLiveData<>(0L);
    private final MutableLiveData<Boolean> localServerRunning = new MutableLiveData<>(false);
    private final MutableLiveData<String> errorMessage = new MutableLiveData<>();

    private LocalKcpServer localServer;
    private int localServerPort;

    private Thread statsUpdateThread;
    private final AtomicBoolean updatingStats = new AtomicBoolean(false);

    public MainViewModel(Application application) {
        super(application);
        localServerPort = ServerConfig.DEFAULT_PORT;
    }

    /**
     * 设置模式
     */
    public void setMode(Mode mode) {
        this.mode.setValue(mode);
        Logger.info(LogConfig.MODULE_UI, "Mode changed to: " + mode);
    }

    /**
     * 获取模式
     */
    public Mode getMode() {
        return mode.getValue();
    }

    /**
     * 连接到远程服务器
     */
    public void connect(String host, int port, String key) {
        Logger.info(LogConfig.MODULE_UI, "Connecting to remote: " + host + ":" + port);

        connectionState.setValue(VpnConnectionState.CONNECTING);

        // 启动 VPN 服务
        ServiceUtil.startVpnService(getApplication(), host, port, key, false);

        startStatsUpdate();
    }

    /**
     * 连接本地服务器
     */
    public void connectLocal() {
        Logger.info(LogConfig.MODULE_UI, "connectLocal() called, port=" + localServerPort);

        connectionState.setValue(VpnConnectionState.CONNECTING);

        Logger.info(LogConfig.MODULE_UI, "Starting VPN service for local mode");
        // 启动 VPN 服务（连接本地）
        ServiceUtil.startVpnService(getApplication(), "127.0.0.1", localServerPort,
                "test-key", true);

        startStatsUpdate();
    }

    /**
     * 断开连接 - 不主动设 DISCONNECTED，等 VPN 服务广播通知
     */
    public void disconnect() {
        Logger.info(LogConfig.MODULE_UI, "Disconnecting");

        connectionState.setValue(VpnConnectionState.DISCONNECTING);

        ServiceUtil.stopVpnService(getApplication());

        stopStatsUpdate();
    }

    /**
     * 启动本地服务器
     */
    public void startLocalServer() {
        Logger.info(LogConfig.MODULE_UI, "startLocalServer() called");

        if (localServer != null && localServer.isRunning()) {
            Logger.warning(LogConfig.MODULE_UI, "Local server already running, port=" + localServerPort);
            return;
        }

        Logger.info(LogConfig.MODULE_UI, "Creating LocalKcpServer on port " + localServerPort);
        localServer = new LocalKcpServer(localServerPort, "test-key");

        Logger.info(LogConfig.MODULE_UI, "Calling localServer.start()");
        if (localServer.start()) {
            localServerRunning.setValue(true);
            Logger.info(LogConfig.MODULE_UI, "Local server started successfully on port " + localServerPort);
        } else {
            errorMessage.setValue("启动本地服务器失败");
            Logger.error(LogConfig.MODULE_UI, "Failed to start local server");
        }
    }

    /**
     * 停止本地服务器
     */
    public void stopLocalServer() {
        if (localServer != null) {
            localServer.stop();
            localServer = null;
            localServerRunning.setValue(false);
            Logger.info(LogConfig.MODULE_UI, "Local server stopped");
        }
    }

    /**
     * 检查本地服务器是否运行
     */
    public boolean isLocalServerRunning() {
        return localServer != null && localServer.isRunning();
    }

    /**
     * 获取本地服务器端口
     */
    public String getLocalServerPort() {
        return String.valueOf(localServerPort);
    }

    /**
     * 启动状态更新线程（使用 AtomicBoolean 防止竞态）
     */
    private void startStatsUpdate() {
        if (!updatingStats.compareAndSet(false, true)) {
            return;
        }

        final long startTime = System.currentTimeMillis();

        statsUpdateThread = new Thread(() -> {
            while (updatingStats.get()) {
                try {
                    Thread.sleep(1000);

                    // 使用绝对时间计算时长，避免与广播值冲突
                    long elapsed = (System.currentTimeMillis() - startTime) / 1000;
                    duration.postValue(elapsed);

                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "Stats-Update");
        statsUpdateThread.start();
    }

    /**
     * 停止状态更新
     */
    private void stopStatsUpdate() {
        updatingStats.set(false);
        if (statsUpdateThread != null) {
            statsUpdateThread.interrupt();
            statsUpdateThread = null;
        }
        duration.setValue(0L);
        uploadBytes.setValue(0L);
        downloadBytes.setValue(0L);
    }

    /**
     * 更新流量统计（由广播调用）
     */
    public void updateStats(long upload, long download) {
        uploadBytes.setValue(upload);
        downloadBytes.setValue(download);
    }

    /**
     * 更新连接时长（由广播调用，会覆盖 stats 线程的计算）
     */
    public void updateDuration(long seconds) {
        duration.setValue(seconds);
    }

    /**
     * 清除错误消息（用于 SingleLiveEvent 模式）
     */
    public void clearErrorMessage() {
        errorMessage.setValue(null);
    }

    /**
     * 设置错误消息
     */
    public void setErrorMessage(String message) {
        errorMessage.setValue(message);
    }

    /**
     * 更新连接状态（由广播调用）
     */
    public void updateConnectionState(VpnConnectionState state) {
        connectionState.setValue(state);
        Logger.info(LogConfig.MODULE_UI, "ViewModel state updated: " + state.getDisplayText());
    }

    /**
     * 获取连接状态
     */
    public LiveData<VpnConnectionState> getConnectionState() {
        return connectionState;
    }

    /**
     * 获取连接时长
     */
    public LiveData<Long> getDuration() {
        return duration;
    }

    /**
     * 获取上传流量
     */
    public LiveData<Long> getUploadBytes() {
        return uploadBytes;
    }

    /**
     * 获取下载流量
     */
    public LiveData<Long> getDownloadBytes() {
        return downloadBytes;
    }

    /**
     * 获取本地服务器运行状态
     */
    public LiveData<Boolean> getLocalServerRunning() {
        return localServerRunning;
    }

    /**
     * 获取错误消息
     */
    public LiveData<String> getErrorMessage() {
        return errorMessage;
    }

    @Override
    protected void onCleared() {
        super.onCleared();
        stopStatsUpdate();
        stopLocalServer();
    }
}