package com.example.kcpvpn.ui.adapters;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.kcpvpn.R;
import com.example.kcpvpn.log.LogEntry;
import com.example.kcpvpn.log.LogLevel;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志列表适配器
 */
public class LogAdapter extends RecyclerView.Adapter<LogAdapter.LogViewHolder> {

    private List<LogEntry> logs;

    private static final int COLOR_DEBUG = Color.GRAY;
    private static final int COLOR_INFO = 0xFF2196F3;      // 蓝色
    private static final int COLOR_WARNING = 0xFFFF9800;   // 橙色
    private static final int COLOR_ERROR = 0xFFF44336;     // 红色

    public LogAdapter(List<LogEntry> logs) {
        this.logs = logs != null ? logs : new ArrayList<>();
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_log, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        LogEntry entry = logs.get(position);
        holder.bind(entry);
    }

    @Override
    public int getItemCount() {
        return logs.size();
    }

    /**
     * 添加日志
     */
    public void addLog(LogEntry entry) {
        logs.add(entry);
        notifyItemInserted(logs.size() - 1);
    }

    /**
     * 更新所有日志
     */
    public void updateLogs(List<LogEntry> newLogs) {
        logs.clear();
        logs.addAll(newLogs);
        notifyDataSetChanged();
    }

    /**
     * 清空日志
     */
    public void clear() {
        logs.clear();
        notifyDataSetChanged();
    }

    /**
     * 日志条目 ViewHolder
     */
    static class LogViewHolder extends RecyclerView.ViewHolder {

        private TextView tvLogContent;
        private TextView tvLogLevel;

        public LogViewHolder(@NonNull View itemView) {
            super(itemView);
            tvLogContent = itemView.findViewById(R.id.tv_log_content);
            tvLogLevel = itemView.findViewById(R.id.tv_log_level);
        }

        public void bind(LogEntry entry) {
            tvLogContent.setText(entry.formatShort());

            // 设置级别颜色
            int color;
            switch (entry.getLevel()) {
                case DEBUG:
                    color = COLOR_DEBUG;
                    break;
                case INFO:
                    color = COLOR_INFO;
                    break;
                case WARNING:
                    color = COLOR_WARNING;
                    break;
                case ERROR:
                    color = COLOR_ERROR;
                    break;
                default:
                    color = COLOR_DEBUG;
                    break;
            }

            tvLogLevel.setBackgroundColor(color);
            tvLogLevel.setText(entry.getLevel().getName());
        }
    }
}