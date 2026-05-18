package com.example.kcpvpn.core.kcp;

import java.util.ArrayList;
import java.util.List;

/**
 * ACK 列表管理 - 移植自 skywind3000/kcp
 */
public class AckList {
    private List<Integer> snList = new ArrayList<>();
    private List<Integer> tsList = new ArrayList<>();

    /**
     * 添加 ACK 条目
     * @param sn 序列号
     * @param ts 时间戳
     */
    public void add(int sn, int ts) {
        snList.add(sn);
        tsList.add(ts);
    }

    /**
     * 获取 ACK 数量
     */
    public int size() {
        return snList.size();
    }

    /**
     * 清空 ACK 列表
     */
    public void clear() {
        snList.clear();
        tsList.clear();
    }

    /**
     * 获取序列号列表
     */
    public List<Integer> getSnList() {
        return snList;
    }

    /**
     * 获取时间戳列表
     */
    public List<Integer> getTsList() {
        return tsList;
    }
}