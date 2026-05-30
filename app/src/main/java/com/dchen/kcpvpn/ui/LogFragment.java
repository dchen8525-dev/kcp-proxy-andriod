package com.dchen.kcpvpn.ui;

import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.os.Bundle;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;

import com.dchen.kcpvpn.R;
import com.google.android.material.snackbar.Snackbar;
import com.dchen.kcpvpn.log.LogBuffer;
import com.dchen.kcpvpn.log.LogEntry;
import com.dchen.kcpvpn.log.LogLevel;
import com.dchen.kcpvpn.log.Logger;
import com.dchen.kcpvpn.ui.adapters.LogAdapter;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.function.Consumer;

/**
 * 日志界面 Fragment
 */
public class LogFragment extends Fragment {

    private MainViewModel viewModel;
    private LogAdapter logAdapter;
    private RecyclerView recyclerView;
    private AutoCompleteTextView spinnerLogLevel;
    private Button btnCopyLog;
    private Button btnClearLog;

    // 初始显示所有日志，使用最低级别 DEBUG（value=0）作为"全部"
    private LogLevel currentLogLevel = LogLevel.DEBUG;
    private Consumer<LogEntry> logListener;
    private final List<LogEntry> pendingUiLogs = Collections.synchronizedList(new ArrayList<>());
    private final android.os.Handler uiLogHandler = new android.os.Handler(android.os.Looper.getMainLooper());
    private volatile boolean uiFlushScheduled;

    private static final String STATE_LOG_LEVEL = "log_level";

    public LogFragment() {
        // Required empty public constructor
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                              Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_log, container, false);
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        viewModel = new ViewModelProvider(requireActivity()).get(MainViewModel.class);

        initViews(view);
        setupRecyclerView();
        setupListeners();

        if (savedInstanceState != null) {
            int levelOrdinal = savedInstanceState.getInt(STATE_LOG_LEVEL, LogLevel.DEBUG.ordinal());
            for (LogLevel level : LogLevel.values()) {
                if (level.ordinal() == levelOrdinal) {
                    currentLogLevel = level;
                    break;
                }
            }
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        // 添加日志监听器（先移除再添加，防止 onResume 重复调用导致监听器堆积）
        removeLogListener();
        createLogListener();
        Logger.getInstance().addListener(logListener);

        // 刷新已有日志
        refreshLogs();
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_LOG_LEVEL, currentLogLevel.ordinal());
    }

    @Override
    public void onPause() {
        super.onPause();
        // 移除日志监听器
        removeLogListener();
        uiLogHandler.removeCallbacksAndMessages(null);
        pendingUiLogs.clear();
        uiFlushScheduled = false;
    }

    /**
     * 移除日志监听器
     */
    private void removeLogListener() {
        if (logListener != null) {
            Logger.getInstance().removeListener(logListener);
        }
    }

    /**
     * 创建日志监听器（使用WeakReference避免内存泄漏）
     */
    private void createLogListener() {
        if (logListener == null) {
            WeakReference<LogFragment> weakThis = new WeakReference<>(this);
            logListener = entry -> {
                LogFragment fragment = weakThis.get();
                if (fragment != null && fragment.isAdded() && !fragment.isRemoving()
                        && fragment.getActivity() != null && !fragment.getActivity().isFinishing()) {
                    if (entry.getLevel().getValue() >= fragment.currentLogLevel.getValue()) {
                        fragment.enqueueLogEntry(entry);
                    }
                }
            };
        }
    }

    /**
     * 初始化视图
     */
    private void initViews(View view) {
        recyclerView = view.findViewById(R.id.recycler_log);
        spinnerLogLevel = view.findViewById(R.id.spinner_log_filter);
        btnCopyLog = view.findViewById(R.id.btn_copy_log);
        btnClearLog = view.findViewById(R.id.btn_clear_log);

        // 设置日志级别下拉：全部=DEBUG最低级, 其他按级别递增
        String[] levels = {"全部", "Debug", "Info", "Warning", "Error"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(requireContext(),
                android.R.layout.simple_dropdown_item_1line, levels);
        spinnerLogLevel.setAdapter(adapter);
        // 根据恢复的currentLogLevel设置初始显示
        int levelIndex = 0;
        switch (currentLogLevel) {
            case DEBUG:
                levelIndex = 0;
                break;
            case INFO:
                levelIndex = 2;
                break;
            case WARNING:
                levelIndex = 3;
                break;
            case ERROR:
                levelIndex = 4;
                break;
        }
        spinnerLogLevel.setText(levels[levelIndex], false);
    }

    /**
     * 设置 RecyclerView
     */
    private void setupRecyclerView() {
        logAdapter = new LogAdapter(new ArrayList<>());
        recyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerView.setAdapter(logAdapter);
    }

    /**
     * 设置监听器
     */
    private void setupListeners() {
        spinnerLogLevel.setOnItemClickListener((parent, view, position, id) -> {
            LogLevel level;
            switch (position) {
                case 0:  // "全部" — 使用最低级别，显示所有日志
                    level = LogLevel.DEBUG;
                    break;
                case 1:
                    level = LogLevel.DEBUG;
                    break;
                case 2:
                    level = LogLevel.INFO;
                    break;
                case 3:
                    level = LogLevel.WARNING;
                    break;
                case 4:
                    level = LogLevel.ERROR;
                    break;
                default:
                    level = LogLevel.DEBUG;
                    break;
            }

            currentLogLevel = level;
            refreshLogs();
        });

        btnCopyLog.setOnClickListener(v -> copyLogsToClipboard());

        btnClearLog.setOnClickListener(v -> {
            Logger.getInstance().clear();
            if (logAdapter != null) {
                logAdapter.clear();
            }
        });
    }

    /**
     * 复制日志到剪贴板
     */
    private void copyLogsToClipboard() {
        if (logAdapter == null || logAdapter.getItemCount() == 0) {
            showSnackbar("没有日志可复制");
            return;
        }

        String logsText = logAdapter.getLogsText();
        ClipboardManager clipboard = (ClipboardManager) requireContext()
                .getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText("KCP VPN Logs", logsText);
            clipboard.setPrimaryClip(clip);
            showSnackbar("已复制 " + logAdapter.getItemCount() + " 条日志到剪贴板");
        }
    }

    /**
     * 安全地显示 Snackbar
     */
    private void showSnackbar(String message) {
        View view = getView();
        if (view != null && isAdded() && !isRemoving()) {
            android.app.Activity activity = getActivity();
            if (activity != null && !activity.isFinishing() && !activity.isDestroyed()) {
                Snackbar.make(view, message, Snackbar.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * 添加日志条目
     */
    private void enqueueLogEntry(LogEntry entry) {
        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded() || isRemoving() || activity.isFinishing()) {
            return;
        }
        pendingUiLogs.add(entry);
        if (!uiFlushScheduled) {
            uiFlushScheduled = true;
            uiLogHandler.postDelayed(this::flushPendingLogs, 300);
        }
    }

    private void flushPendingLogs() {
        uiFlushScheduled = false;
        List<LogEntry> batch;
        synchronized (pendingUiLogs) {
            if (pendingUiLogs.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pendingUiLogs);
            pendingUiLogs.clear();
        }

        for (LogEntry entry : batch) {
            if (logAdapter == null || !isAdded() || isRemoving()) {
                return;
            }
            logAdapter.addLog(entry);
        }
        if (recyclerView != null && logAdapter != null && logAdapter.getItemCount() > 0) {
            recyclerView.scrollToPosition(logAdapter.getItemCount() - 1);
        }
    }

    /**
     * 刷新日志
     */
    private void refreshLogs() {
        if (logAdapter == null || recyclerView == null) return;

        List<LogEntry> logs = Logger.getInstance().getBuffer().getByLevel(currentLogLevel);
        logAdapter.updateLogs(logs);

        // 滚动到底部
        if (!logs.isEmpty()) {
            recyclerView.scrollToPosition(logs.size() - 1);
        }
    }
}
