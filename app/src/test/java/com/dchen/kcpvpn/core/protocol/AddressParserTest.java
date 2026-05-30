package com.dchen.kcpvpn.core.protocol;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AddressParserTest {
    @Test
    public void parsesIpv4() {
        byte[] data = new byte[]{Socks5.SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0x01, (byte) 0xBB};
        AddressParser.ParsedAddress addr = AddressParser.parse(data, 0, data.length);
        assertEquals("1.2.3.4", addr.host);
        assertEquals(443, addr.port);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTruncatedIpv4() {
        AddressParser.parse(new byte[]{Socks5.SOCKS5_ATYP_IPV4, 1, 2}, 0, 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsEmptyDomain() {
        AddressParser.parse(new byte[]{Socks5.SOCKS5_ATYP_DOMAIN, 0, 0, 53}, 0, 4);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTruncatedDomain() {
        AddressParser.parse(new byte[]{Socks5.SOCKS5_ATYP_DOMAIN, 5, 'a'}, 0, 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTruncatedIpv6() {
        AddressParser.parse(new byte[]{Socks5.SOCKS5_ATYP_IPV6, 0, 1}, 0, 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnknownAddressType() {
        AddressParser.parse(new byte[]{99, 0, 0}, 0, 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsEmptyPayload() {
        AddressParser.parse(new byte[0], 0, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsDomainLengthTooLong() {
        AddressParser.parse(new byte[]{Socks5.SOCKS5_ATYP_DOMAIN, 10, 'a', 'b'}, 0, 4);
    }
}
