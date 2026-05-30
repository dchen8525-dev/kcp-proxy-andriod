package com.dchen.kcpvpn.vpn.cppremote;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

final class CppSocks5ResponseBuffer {
    enum Status {
        INCOMPLETE,
        COMPLETE,
        INVALID
    }

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int responseLength = -1;
    private int reply = -1;

    Status append(byte[] data) {
        if (data == null || data.length == 0) {
            return Status.INCOMPLETE;
        }
        buffer.write(data, 0, data.length);
        byte[] bytes = buffer.toByteArray();
        int parseResult = CppSocks5RequestBuilder.socks5ResponseLength(bytes);
        if (parseResult == CppSocks5RequestBuilder.SOCKS5_RESPONSE_INCOMPLETE) {
            return Status.INCOMPLETE;
        }
        if (parseResult < 0) {
            return Status.INVALID;
        }
        responseLength = parseResult;
        reply = bytes[1] & 0xFF;
        return Status.COMPLETE;
    }

    int reply() {
        return reply;
    }

    byte[] extraPayload() {
        byte[] bytes = buffer.toByteArray();
        if (responseLength < 0 || bytes.length <= responseLength) {
            return new byte[0];
        }
        return Arrays.copyOfRange(bytes, responseLength, bytes.length);
    }
}
