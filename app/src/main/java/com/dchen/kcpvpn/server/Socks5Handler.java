package com.dchen.kcpvpn.server;

import com.dchen.kcpvpn.core.protocol.AddressParser;
import com.dchen.kcpvpn.core.protocol.KcpFrame;
import com.dchen.kcpvpn.core.protocol.Socks5;
import com.dchen.kcpvpn.core.session.SocketProtector;
import com.dchen.kcpvpn.log.LogConfig;
import com.dchen.kcpvpn.log.Logger;

import java.nio.ByteBuffer;

/**
 * 解析 OPEN frame payload。payload 复用现有 SOCKS5 CONNECT 请求格式来携带目标地址。
 */
public class Socks5Handler {

    public static void handleOpenFrame(ServerSession session, KcpFrame frame,
                                       ServerConnectionManager connectionManager,
                                       SocketProtector socketProtector) {
        byte[] data = frame.getPayload();
        long connectionId = frame.getConnectionId();

        if (data == null || data.length < 4) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "OPEN payload too short: connectionId="
                    + connectionId + ", payloadLength=" + (data == null ? 0 : data.length));
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        byte ver = buf.get();
        byte cmd = buf.get();
        buf.get();
        byte atyp = buf.get();

        if (ver != Socks5.SOCKS5_VERSION || cmd != Socks5.SOCKS5_CMD_CONNECT) {
            Logger.warning(LogConfig.MODULE_SOCKS5, "Invalid OPEN SOCKS5 request: connectionId="
                    + connectionId + ", ver=" + ver + ", cmd=" + cmd + ", atyp=" + atyp);
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
            return;
        }

        try {
            AddressParser.ParsedAddress addr = AddressParser.parse(data, 3, data.length);
            if (addr.host == null || addr.host.isEmpty()) {
                Logger.warning(LogConfig.MODULE_SOCKS5, "OPEN empty host: connectionId=" + connectionId);
                session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
                return;
            }

            Logger.info(LogConfig.MODULE_SOCKS5, "OPEN frame: connectionId=" + connectionId
                    + ", dst=" + addr.host + ":" + addr.port
                    + ", payloadLength=" + frame.getPayloadLength());
            connectionManager.openConnection(connectionId, addr.host, addr.port, session, socketProtector);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_SOCKS5, "Parse OPEN error: connectionId="
                    + connectionId + ", error=" + e.getMessage());
            session.sendFrame(new KcpFrame(KcpFrame.TYPE_RESET, connectionId, null));
        }
    }
}
