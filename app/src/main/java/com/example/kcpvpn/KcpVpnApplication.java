package com.example.kcpvpn;

import android.app.Application;

import com.example.kcpvpn.log.Logger;

/**
 * 应用入口 - 确保全局初始化
 */
public class KcpVpnApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        // 在Application启动时初始化日志系统
        Logger.init(getApplicationContext());
    }
}