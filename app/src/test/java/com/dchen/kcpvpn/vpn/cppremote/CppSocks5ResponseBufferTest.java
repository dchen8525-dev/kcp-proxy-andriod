package com.dchen.kcpvpn.vpn.cppremote;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CppSocks5ResponseBufferTest {
    @Test
    public void completeIpv4ResponseIsAccepted() {
        CppSocks5ResponseBuffer buffer = new CppSocks5ResponseBuffer();

        CppSocks5ResponseBuffer.Status status = buffer.append(new byte[] {
                0x05, 0x00, 0x00, 0x01,
                127, 0, 0, 1,
                0x1F, (byte) 0xBB
        });

        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE, status);
        assertEquals(0, buffer.reply());
        assertArrayEquals(new byte[0], buffer.extraPayload());
    }

    @Test
    public void splitResponseByteByByteIsAccepted() {
        CppSocks5ResponseBuffer buffer = new CppSocks5ResponseBuffer();
        byte[] response = new byte[] {
                0x05, 0x00, 0x00, 0x01,
                127, 0, 0, 1,
                0x1F, (byte) 0xBB
        };

        for (int i = 0; i < response.length - 1; i++) {
            assertEquals(CppSocks5ResponseBuffer.Status.INCOMPLETE,
                    buffer.append(new byte[] { response[i] }));
        }

        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE,
                buffer.append(new byte[] { response[response.length - 1] }));
        assertEquals(0, buffer.reply());
    }

    @Test
    public void responseWithExtraPayloadPreservesExtra() {
        CppSocks5ResponseBuffer buffer = new CppSocks5ResponseBuffer();

        CppSocks5ResponseBuffer.Status status = buffer.append(new byte[] {
                0x05, 0x00, 0x00, 0x01,
                127, 0, 0, 1,
                0x1F, (byte) 0xBB,
                0x11, 0x22, 0x33
        });

        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE, status);
        assertArrayEquals(new byte[] { 0x11, 0x22, 0x33 }, buffer.extraPayload());
    }

    @Test
    public void failureReplyIsCompleteAndExposesReply() {
        CppSocks5ResponseBuffer buffer = new CppSocks5ResponseBuffer();

        CppSocks5ResponseBuffer.Status status = buffer.append(new byte[] {
                0x05, 0x05, 0x00, 0x01,
                0, 0, 0, 0,
                0, 0
        });

        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE, status);
        assertEquals(5, buffer.reply());
    }

    @Test
    public void invalidVersionIsRejected() {
        CppSocks5ResponseBuffer buffer = new CppSocks5ResponseBuffer();

        assertEquals(CppSocks5ResponseBuffer.Status.INVALID,
                buffer.append(new byte[] { 0x04, 0x00, 0x00, 0x01 }));
    }

    @Test
    public void domainAndIpv6ResponsesAreAccepted() {
        CppSocks5ResponseBuffer domain = new CppSocks5ResponseBuffer();
        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE,
                domain.append(new byte[] {
                        0x05, 0x00, 0x00, 0x03,
                        0x03, 'a', 'b', 'c',
                        0x01, (byte) 0xBB
                }));

        CppSocks5ResponseBuffer ipv6 = new CppSocks5ResponseBuffer();
        assertEquals(CppSocks5ResponseBuffer.Status.COMPLETE,
                ipv6.append(new byte[] {
                        0x05, 0x00, 0x00, 0x04,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 1,
                        0x01, (byte) 0xBB
                }));
    }
}
