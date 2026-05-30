package com.dchen.kcpvpn;

import android.app.Application;

import com.dchen.kcpvpn.log.LogLevel;
import com.dchen.kcpvpn.log.Logger;

/**
 * 应用入口 - 确保全局初始化
 */
public class KcpVpnApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        // 在Application启动时初始化日志系统
        Logger.init(getApplicationContext());
        Logger.getInstance().setMinLevel(LogLevel.fromName(BuildConfig.DEFAULT_LOG_LEVEL));
    }
}
