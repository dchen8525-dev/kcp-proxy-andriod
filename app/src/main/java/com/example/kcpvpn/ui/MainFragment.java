package com.example.kcpvpn.ui;

import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.example.kcpvpn.R;
import com.example.kcpvpn.log.LogConfig;
import com.example.kcpvpn.log.Logger;
import com.example.kcpvpn.util.NetworkUtil;
import com.example.kcpvpn.util.ServiceUtil;
import com.example.kcpvpn.vpn.VpnConnectionState;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

/**
 * 主界面 Fragment
 */
public class MainFragment extends Fragment {

    private MainViewModel viewModel;

    // UI 元素
    private MaterialButtonToggleGroup modeToggleGroup;
    private MaterialButton btnRemoteMode;
    private MaterialButton btnLocalMode;

    // 外网模式配置
    private LinearLayout remoteConfigLayout;
    private TextInputEditText etServerIp;
    private TextInputEditText etServerPort;
    private TextInputEditText etKey;

    // 本地模式配置
    private LinearLayout localConfigLayout;
    private TextView tvLocalPort;
    private MaterialButton btnStartLocalServer;
    private MaterialButton btnStopLocalServer;

    // 连接控制
    private MaterialButton btnConnect;
    private MaterialButton btnDisconnect;
    private TextView tvConnectionState;

    // 状态显示
    private TextView tvDuration;
    private TextView tvUpload;
    private TextView tvDownload;

    // VPN 授权请求码
    private static final int VPN_AUTH_REQUEST_CODE = 1001;
    private static final String STATE_WAITING_VPN_AUTH = "waiting_vpn_auth";
    private static final String STATE_SERVER_IP = "server_ip";
    private static final String STATE_SERVER_PORT = "server_port";
    private static final String STATE_KEY = "key";
    private boolean waitingVpnAuth = false;

    public MainFragment() {
        // Required empty public constructor
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                              Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_main, container, false);
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        // 获取 ViewModel
        viewModel = new ViewModelProvider(requireActivity()).get(MainViewModel.class);

        initViews(view);
        setupListeners();
        setupObservers();

        // 恢复模式选择
        MainViewModel.Mode savedMode = viewModel.getMode();
        if (savedMode == MainViewModel.Mode.LOCAL) {
            modeToggleGroup.check(R.id.btn_local_mode);
        } else {
            modeToggleGroup.check(R.id.btn_remote_mode);
        }
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(STATE_WAITING_VPN_AUTH, waitingVpnAuth);
        // 保存输入框内容
        if (etServerIp != null) {
            outState.putString(STATE_SERVER_IP, etServerIp.getText() != null
                    ? etServerIp.getText().toString() : "");
        }
        if (etServerPort != null) {
            outState.putString(STATE_SERVER_PORT, etServerPort.getText() != null
                    ? etServerPort.getText().toString() : "");
        }
        if (etKey != null) {
            outState.putString(STATE_KEY, etKey.getText() != null
                    ? etKey.getText().toString() : "");
        }
    }

    @Override
    public void onViewStateRestored(Bundle savedInstanceState) {
        super.onViewStateRestored(savedInstanceState);
        if (savedInstanceState != null) {
            waitingVpnAuth = savedInstanceState.getBoolean(STATE_WAITING_VPN_AUTH, false);
            // 恢复输入框内容
            String ip = savedInstanceState.getString(STATE_SERVER_IP);
            String port = savedInstanceState.getString(STATE_SERVER_PORT);
            String key = savedInstanceState.getString(STATE_KEY);
            if (ip != null && etServerIp != null) {
                etServerIp.setText(ip);
            }
            if (port != null && etServerPort != null) {
                etServerPort.setText(port);
            }
            if (key != null && etKey != null) {
                etKey.setText(key);
            }
        }
    }

    /**
     * 初始化视图
     */
    private void initViews(View view) {
        // 模式切换
        modeToggleGroup = view.findViewById(R.id.mode_toggle_group);
        btnRemoteMode = view.findViewById(R.id.btn_remote_mode);
        btnLocalMode = view.findViewById(R.id.btn_local_mode);

        // 外网模式配置
        remoteConfigLayout = view.findViewById(R.id.remote_config_layout);
        etServerIp = view.findViewById(R.id.et_server_ip);
        etServerPort = view.findViewById(R.id.et_server_port);
        etKey = view.findViewById(R.id.et_key);

        // 本地模式配置
        localConfigLayout = view.findViewById(R.id.local_config_layout);
        tvLocalPort = view.findViewById(R.id.tv_local_port);
        btnStartLocalServer = view.findViewById(R.id.btn_start_local_server);
        btnStopLocalServer = view.findViewById(R.id.btn_stop_local_server);

        // 连接控制
        btnConnect = view.findViewById(R.id.btn_connect);
        btnDisconnect = view.findViewById(R.id.btn_disconnect);
        tvConnectionState = view.findViewById(R.id.tv_connection_state);

        // 状态显示
        tvDuration = view.findViewById(R.id.tv_duration);
        tvUpload = view.findViewById(R.id.tv_upload);
        tvDownload = view.findViewById(R.id.tv_download);
    }

    /**
     * 设置监听器
     */
    private void setupListeners() {
        // 模式切换
        modeToggleGroup.addOnButtonCheckedListener((group, checkedId, isChecked) -> {
            if (isChecked) {
                if (checkedId == R.id.btn_remote_mode) {
                    viewModel.setMode(MainViewModel.Mode.REMOTE);
                    remoteConfigLayout.setVisibility(View.VISIBLE);
                    localConfigLayout.setVisibility(View.GONE);
                } else if (checkedId == R.id.btn_local_mode) {
                    viewModel.setMode(MainViewModel.Mode.LOCAL);
                    remoteConfigLayout.setVisibility(View.GONE);
                    localConfigLayout.setVisibility(View.VISIBLE);
                }
            }
        });

        // 启动本地服务
        btnStartLocalServer.setOnClickListener(v -> {
            viewModel.startLocalServer();
        });

        // 停止本地服务
        btnStopLocalServer.setOnClickListener(v -> {
            viewModel.stopLocalServer();
        });

        // 连接按钮
        btnConnect.setOnClickListener(v -> {
            if (waitingVpnAuth) {
                return;
            }

            // 检查网络
            if (!NetworkUtil.isNetworkAvailable(requireContext())) {
                showSnackbar("网络不可用");
                return;
            }

            // 检查 VPN 授权
            Intent vpnIntent = ServiceUtil.checkVpnAuthorization(requireContext());
            if (vpnIntent != null) {
                waitingVpnAuth = true;
                btnConnect.setEnabled(false);
                startActivityForResult(vpnIntent, VPN_AUTH_REQUEST_CODE);
            } else {
                startConnection();
            }
        });

        // 断开按钮
        btnDisconnect.setOnClickListener(v -> {
            viewModel.disconnect();
        });
    }

    /**
     * 设置观察者
     */
    private void setupObservers() {
        // 连接状态
        viewModel.getConnectionState().observe(getViewLifecycleOwner(), state -> {
            tvConnectionState.setText(state.getDisplayText());

            // 更新按钮状态
            boolean isConnected = state == VpnConnectionState.CONNECTED;
            boolean isConnecting = state == VpnConnectionState.CONNECTING
                    || state == VpnConnectionState.RECONNECTING;
            boolean isDisconnecting = state == VpnConnectionState.DISCONNECTING;

            waitingVpnAuth = false;
            btnConnect.setEnabled(!isConnected && !isConnecting && !isDisconnecting);
            btnDisconnect.setEnabled(isConnected || isConnecting);
        });

        // 连接时长
        viewModel.getDuration().observe(getViewLifecycleOwner(), duration -> {
            tvDuration.setText(formatDuration(duration));
        });

        // 上传流量
        viewModel.getUploadBytes().observe(getViewLifecycleOwner(), bytes -> {
            tvUpload.setText(formatBytes(bytes));
        });

        // 下载流量
        viewModel.getDownloadBytes().observe(getViewLifecycleOwner(), bytes -> {
            tvDownload.setText(formatBytes(bytes));
        });

        // 本地服务状态
        viewModel.getLocalServerRunning().observe(getViewLifecycleOwner(), running -> {
            btnStartLocalServer.setEnabled(!running);
            btnStopLocalServer.setEnabled(running);
            tvLocalPort.setText(running ? viewModel.getLocalServerPort() : "未启动");
        });

        // 错误消息（一次性事件，防止配置变化时重复弹出）
        viewModel.getErrorMessage().observe(getViewLifecycleOwner(), event -> {
            if (event != null) {
                String message = event.getContentIfNotHandled();
                if (message != null && !message.isEmpty()) {
                    showSnackbarLong(message);
                }
            }
        });
    }

    /**
     * 开始连接
     */
    private void startConnection() {
        MainViewModel.Mode mode = viewModel.getMode();

        if (mode == MainViewModel.Mode.REMOTE) {
            // 外网模式
            String host = etServerIp.getText() != null ? etServerIp.getText().toString().trim() : "";
            String portStr = etServerPort.getText() != null ? etServerPort.getText().toString().trim() : "";
            String key = etKey.getText() != null ? etKey.getText().toString().trim() : "";

            if (host.isEmpty() || portStr.isEmpty() || key.isEmpty()) {
                showSnackbar("请填写完整配置");
                return;
            }

            int port;
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                showSnackbar("端口格式错误，请输入数字");
                return;
            }

            if (port < 1 || port > 65535) {
                showSnackbar("端口范围应为 1-65535");
                return;
            }

            viewModel.connect(host, port, key);

        } else if (mode == MainViewModel.Mode.LOCAL) {
            // 本地模式
            if (!viewModel.isLocalServerRunning()) {
                showSnackbar("请先启动本地服务");
                return;
            }

            viewModel.connectLocal();
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == VPN_AUTH_REQUEST_CODE) {
            waitingVpnAuth = false;
            if (resultCode == Activity.RESULT_OK) {
                Logger.info(LogConfig.MODULE_UI, "VPN authorization granted");
                startConnection();
            } else {
                Logger.warning(LogConfig.MODULE_UI, "VPN authorization denied");
                View view = getView();
                if (view != null && isAdded()) {
                    Snackbar.make(view, "VPN 授权被拒绝", Snackbar.LENGTH_SHORT).show();
                }
            }
        }
    }

    /**
     * 格式化时长
     */
    private String formatDuration(long seconds) {
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;

        if (hours > 0) {
            return String.format("%d:%02d:%02d", hours, minutes, secs);
        } else {
            return String.format("%02d:%02d", minutes, secs);
        }
    }

    /**
     * 格式化字节
     */
    private String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        } else {
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * 安全地显示 Snackbar，避免 View 已销毁时崩溃
     */
    private void showSnackbar(String message) {
        View view = getView();
        if (view != null && isAdded()) {
            Snackbar.make(view, message, Snackbar.LENGTH_SHORT).show();
        }
    }

    /**
     * 安全地显示长时 Snackbar
     */
    private void showSnackbarLong(String message) {
        View view = getView();
        if (view != null && isAdded()) {
            Snackbar.make(view, message, Snackbar.LENGTH_LONG).show();
        }
    }
}
