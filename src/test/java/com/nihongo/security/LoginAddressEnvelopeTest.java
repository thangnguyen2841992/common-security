package com.nihongo.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import java.time.*;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class LoginAddressEnvelopeTest {
    InternalCredentials key(int seed) {
        byte[] bytes = new byte[32]; bytes[0] = (byte) seed;
        return new InternalCredentials(new MockEnvironment().withProperty("security.internal.key", Base64.getEncoder().encodeToString(bytes)));
    }
    Clock at(long second) { return Clock.fixed(Instant.ofEpochSecond(second), ZoneOffset.UTC); }

    @Test void transfersLoopbackAndLanSnapshotWithoutExposingInternalCredential() {
        var codec = new LoginAddressEnvelope(key(1), at(1000));
        String header = codec.sign("POST", "/api/auth/login", "127.0.0.1", "192.168.1.8,10.0.0.4");
        assertFalse(header.contains(key(1).value()));
        assertEquals(new LoginAddressEnvelope.Address("127.0.0.1", "192.168.1.8,10.0.0.4"), codec.verify(header, "POST", "/api/auth/login").orElseThrow());
        String ipv6 = codec.sign("POST", "/api/auth/mfa/verify", "::1", "");
        assertTrue(codec.verify(ipv6, "POST", "/api/auth/mfa/verify").isPresent());
    }

    @Test void rejectsForgedExpiredWrongKeyAndDifferentRequestMetadata() {
        var codec = new LoginAddressEnvelope(key(1), at(1000));
        String header = codec.sign("POST", "/api/auth/login", "127.0.0.1", "192.168.1.8");
        assertTrue(codec.verify(header.substring(0, header.length() - 2), "POST", "/api/auth/login").isEmpty());
        assertTrue(new LoginAddressEnvelope(key(2), at(1000)).verify(header, "POST", "/api/auth/login").isEmpty());
        assertTrue(new LoginAddressEnvelope(key(1), at(1181)).verify(header, "POST", "/api/auth/login").isEmpty());
        assertTrue(new LoginAddressEnvelope(key(1), at(960)).verify(header, "POST", "/api/auth/login").isEmpty());
        assertTrue(codec.verify(header, "GET", "/api/auth/login").isEmpty());
        assertTrue(codec.verify(header, "POST", "/api/auth/mfa/verify").isEmpty());
        for (String malformed : new String[]{"", "192.168.1.8", "not-base64.not-base64", "x".repeat(2049)})
            assertTrue(codec.verify(malformed, "POST", "/api/auth/login").isEmpty());
        assertTrue(codec.verify(null, "POST", "/api/auth/login").isEmpty());
    }
}
