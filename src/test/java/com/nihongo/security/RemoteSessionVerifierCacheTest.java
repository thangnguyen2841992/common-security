package com.nihongo.security;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RemoteSessionVerifierCacheTest {
    private static Jwt token(String sid) {
        return Jwt.withTokenValue("token-" + sid).header("alg", "RS256").subject("owner").claim("sessionId", sid)
                .claim("roles", List.of("USER")).claim("type", "access").expiresAt(Instant.now().plusSeconds(60)).build();
    }

    private static RemoteSessionVerifier verifier(int port, long ttl) {
        var env = new MockEnvironment()
                .withProperty("security.internal.key", Base64.getEncoder().encodeToString(new byte[32]))
                .withProperty("auth.session-validation-url", "http://127.0.0.1:" + port + "/validate")
                .withProperty("auth.session-cache-ttl", Long.toString(ttl));
        return new RemoteSessionVerifier(env, new InternalCredentials(env));
    }

    @Test
    void validSessionIsCachedButFailuresAreNot() throws Exception {
        var calls = new AtomicInteger();
        var status = new AtomicInteger(204);
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/validate", exchange -> {
            calls.incrementAndGet();
            exchange.sendResponseHeaders(status.get(), -1);
            exchange.close();
        });
        server.start();
        try {
            var verifier = verifier(server.getAddress().getPort(), 5000);
            assertEquals(204, verifier.status(token("a")));
            assertEquals(204, verifier.status(token("a")));
            assertEquals(1, calls.get(), "second check within TTL must not hit the auth service");

            status.set(401);
            assertEquals(401, verifier.status(token("b")));
            assertEquals(401, verifier.status(token("b")));
            assertEquals(3, calls.get(), "rejected sessions are never cached");

            var uncached = verifier(server.getAddress().getPort(), 0);
            status.set(204);
            uncached.status(token("c"));
            uncached.status(token("c"));
            assertEquals(5, calls.get(), "TTL 0 disables the cache");
        } finally {
            server.stop(0);
        }
    }
}
