package com.dchen.kcpvpn.util;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

import com.dchen.kcpvpn.vpn.KcpVpnService;

/**
 * VPN 服务工具类
 */
public class ServiceUtil {

    /**
     * 检查 VPN 授权状态
     * @return Intent 需要授权时返回授权 Intent，已授权返回 null
     */
    public static Intent checkVpnAuthorization(Context context) {
        return VpnService.prepare(context);
    }

    /**
     * 启动 VPN 服务
     * @param context 上下文
     * @param serverHost 服务端地址
     * @param serverPort 服务端端口
     * @param key 密钥
     * @param localMode 是否本地模式
     */
    public static void startVpnService(Context context, String serverHost, int serverPort,
                                        String key, boolean localMode) {
        Intent intent = new Intent(context, KcpVpnService.class);
        intent.putExtra("server_host", serverHost);
        intent.putExtra("server_port", serverPort);
        intent.putExtra("key", key);
        intent.putExtra("local_mode", localMode);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    /**
     * 停止 VPN 服务
     */
    public static void stopVpnService(Context context) {
        Intent intent = new Intent(context, KcpVpnService.class);
        intent.setAction(KcpVpnService.ACTION_STOP);
        context.startService(intent);
    }

    /**
     * 检查 VPN 服务是否运行
     * 注意：这只是检查服务是否启动，不是 VPN 是否连接
     */
    public static boolean isVpnServiceRunning(Context context) {
        // 通过查询服务状态来判断
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (manager != null) {
            for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
                if (KcpVpnService.class.getName().equals(service.service.getClassName())) {
                    return true;
                }
            }
        }
        return false;
    }
}
