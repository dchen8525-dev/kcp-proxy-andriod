package com.dchen.kcpvpn.ui;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.ViewModelProvider;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;

import com.dchen.kcpvpn.R;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;
import com.dchen.kcpvpn.util.ServiceUtil;
import com.dchen.kcpvpn.vpn.VpnConnectionState;
import com.dchen.kcpvpn.vpn.VpnStateBroadcast;
import com.google.android.material.bottomnavigation.BottomNavigationView;

/**
 * 主 Activity
 */
public class MainActivity extends AppCompatActivity {

    private MainViewModel viewModel;
    private BottomNavigationView bottomNav;

    private Fragment activeFragment;

    private BroadcastReceiver stateReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Logger已在Application中初始化，这里只记录日志
        Logger.info(LogConfig.MODULE_UI, "MainActivity onCreate");

        // 创建 ViewModel
        viewModel = new ViewModelProvider(this).get(MainViewModel.class);

        // 设置底部导航
        bottomNav = findViewById(R.id.bottom_navigation);
        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_main) {
                switchFragment(getMainFragment());
                return true;
            } else if (itemId == R.id.nav_log) {
                switchFragment(getLogFragment());
                return true;
            }
            return false;
        });

        // 初始化Fragment显示
        initFragments();

        // 注册 VPN 状态广播接收器
        registerStateReceiver();

        // 检测后台是否有残留的 VPN 服务，同步 UI 状态
        syncVpnServiceState();
    }

    /**
     * 获取或创建MainFragment
     */
    private MainFragment getMainFragment() {
        FragmentManager fm = getSupportFragmentManager();
        MainFragment fragment = (MainFragment) fm.findFragmentByTag("main");
        if (fragment == null) {
            fragment = new MainFragment();
        }
        return fragment;
    }

    /**
     * 获取或创建LogFragment
     */
    private LogFragment getLogFragment() {
        FragmentManager fm = getSupportFragmentManager();
        LogFragment fragment = (LogFragment) fm.findFragmentByTag("log");
        if (fragment == null) {
            fragment = new LogFragment();
        }
        return fragment;
    }

    /**
     * 初始化Fragment
     */
    private void initFragments() {
        FragmentManager fm = getSupportFragmentManager();
        MainFragment main = getMainFragment();
        LogFragment log = getLogFragment();

        // 如果Fragment不在FragmentManager中，添加它们
        if (!main.isAdded()) {
            FragmentTransaction transaction = fm.beginTransaction();
            transaction.add(R.id.fragment_container, main, "main");
            if (!log.isAdded()) {
                transaction.add(R.id.fragment_container, log, "log");
                transaction.hide(log);
            }
            transaction.commitNow();
            activeFragment = main;
        } else if (!log.isAdded()) {
            FragmentTransaction transaction = fm.beginTransaction();
            transaction.add(R.id.fragment_container, log, "log");
            transaction.hide(log);
            transaction.commitNow();
        }

        // 确定当前显示的Fragment
        if (main.isVisible()) {
            activeFragment = main;
        } else if (log.isVisible()) {
            activeFragment = log;
        } else {
            activeFragment = main;
        }
    }

    /**
     * 切换Fragment（使用show/hide，避免重建）
     */
    private void switchFragment(Fragment targetFragment) {
        if (targetFragment == activeFragment) {
            return;
        }

        FragmentManager fm = getSupportFragmentManager();
        if (fm.isStateSaved()) {
            return;
        }

        FragmentTransaction transaction = fm.beginTransaction();

        transaction.hide(activeFragment);
        transaction.show(targetFragment);
        transaction.commitNowAllowingStateLoss();

        activeFragment = targetFragment;
    }

    /**
     * 注册状态广播接收器
     */
    private void registerStateReceiver() {
        stateReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (VpnStateBroadcast.ACTION_STATE_CHANGED.equals(intent.getAction())) {
                    String stateName = intent.getStringExtra(VpnStateBroadcast.EXTRA_STATE);
                    long uploadBytes = intent.getLongExtra(VpnStateBroadcast.EXTRA_UPLOAD_BYTES, 0);
                    long downloadBytes = intent.getLongExtra(VpnStateBroadcast.EXTRA_DOWNLOAD_BYTES, 0);
                    long duration = intent.getLongExtra(VpnStateBroadcast.EXTRA_DURATION, 0);

                    if (stateName == null || stateName.isEmpty()) {
                        Logger.error(LogConfig.MODULE_UI, "Broadcast received with null state");
                        return;
                    }

                    try {
                        VpnConnectionState state = VpnConnectionState.valueOf(stateName);
                        viewModel.updateConnectionState(state);
                        viewModel.updateStats(uploadBytes, downloadBytes);
                        viewModel.updateDuration(duration);
                    } catch (IllegalArgumentException e) {
                        Logger.error(LogConfig.MODULE_UI, "Unknown VPN state: " + stateName);
                    }
                }
            }
        };

        IntentFilter filter = new IntentFilter(VpnStateBroadcast.ACTION_STATE_CHANGED);
        LocalBroadcastManager.getInstance(this).registerReceiver(stateReceiver, filter);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (stateReceiver != null) {
            LocalBroadcastManager.getInstance(this).unregisterReceiver(stateReceiver);
        }
    }

    /**
     * 同步 VPN 服务的真实状态（进程死亡后恢复时调用）
     */
    private void syncVpnServiceState() {
        if (ServiceUtil.isVpnServiceRunning(this)) {
            Logger.info(LogConfig.MODULE_UI, "VPN service is running in background, syncing UI state");
            viewModel.updateConnectionState(VpnConnectionState.CONNECTED);
            // 启动统计更新以刷新 UI 数据
            viewModel.startStatsUpdateAfterRestore();
        }
    }
}