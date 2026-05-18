package com.example.kcpvpn.ui;

import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;

import com.example.kcpvpn.R;
import com.example.kcpvpn.log.LogBuffer;
import com.example.kcpvpn.log.LogEntry;
import com.example.kcpvpn.log.LogLevel;
import com.example.kcpvpn.log.Logger;
import com.example.kcpvpn.ui.adapters.LogAdapter;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * 日志界面 Fragment
 */
public class LogFragment extends Fragment {

    private MainViewModel viewModel;
    private LogAdapter logAdapter;
    private RecyclerView recyclerView;
    private AutoCompleteTextView spinnerLogLevel;
    private Button btnClearLog;

    // 初始显示所有日志，使用最低级别 DEBUG（value=0）作为"全部"
    private LogLevel currentLogLevel = LogLevel.DEBUG;
    private Consumer<LogEntry> logListener;

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

        try {
            viewModel = new ViewModelProvider(requireActivity()).get(MainViewModel.class);
        } catch (Exception e) {
            // Fragment可能还没attach到Activity
        }

        initViews(view);
        setupRecyclerView();
        setupListeners();
    }

    @Override
    public void onResume() {
        super.onResume();
        // 添加日志监听器
        createLogListener();
        Logger.getInstance().addListener(logListener);

        // 刷新已有日志
        refreshLogs();
    }

    @Override
    public void onPause() {
        super.onPause();
        // 移除日志监听器
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
                if (fragment != null && fragment.isAdded() && fragment.getActivity() != null) {
                    if (entry.getLevel().getValue() >= fragment.currentLogLevel.getValue()) {
                        fragment.addLogEntry(entry);
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
        btnClearLog = view.findViewById(R.id.btn_clear_log);

        // 设置日志级别下拉：全部=DEBUG最低级, 其他按级别递增
        String[] levels = {"全部", "Debug", "Info", "Warning", "Error"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(requireContext(),
                android.R.layout.simple_dropdown_item_1line, levels);
        spinnerLogLevel.setAdapter(adapter);
        spinnerLogLevel.setText(levels[0], false);
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

        btnClearLog.setOnClickListener(v -> {
            Logger.getInstance().clear();
            if (logAdapter != null) {
                logAdapter.clear();
            }
        });
    }

    /**
     * 添加日志条目
     */
    private void addLogEntry(LogEntry entry) {
        if (getActivity() != null && isAdded()) {
            getActivity().runOnUiThread(() -> {
                if (logAdapter != null && isAdded()) {
                    logAdapter.addLog(entry);
                    recyclerView.scrollToPosition(logAdapter.getItemCount() - 1);
                }
            });
        }
    }

    /**
     * 刷新日志
     */
    private void refreshLogs() {
        if (logAdapter == null) return;

        List<LogEntry> logs = Logger.getInstance().getBuffer().getByLevel(currentLogLevel);
        logAdapter.updateLogs(logs);

        // 滚动到底部
        if (!logs.isEmpty()) {
            recyclerView.scrollToPosition(logs.size() - 1);
        }
    }
}
