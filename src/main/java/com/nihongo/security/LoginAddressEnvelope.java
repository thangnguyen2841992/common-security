package com.nihongo.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;
import java.util.Optional;

/** Signed audit metadata only. This envelope never authorizes a request. */
public final class LoginAddressEnvelope {
    public static final String HEADER = "X-Nihongo-Login-Address";
    public record Address(String ip, String localAddresses) {}
    private final byte[] key;
    private final Clock clock;

    public LoginAddressEnvelope(InternalCredentials credentials) { this(credentials, Clock.systemUTC()); }
    public LoginAddressEnvelope(InternalCredentials credentials, Clock clock) {
        this.key = credentials.value().getBytes(StandardCharsets.US_ASCII);
        this.clock = clock;
    }

    public String sign(String method, String path, String ip, String localAddresses) {
        if (!numeric(ip) || !validLocalAddresses(localAddresses)) throw new IllegalArgumentException("Invalid audit address");
        String payload = String.join("\n", "login-address-v1", Long.toString(clock.instant().getEpochSecond()), method, path, ip, localAddresses);
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) + "."
            + Base64.getUrlEncoder().withoutPadding().encodeToString(mac(bytes));
    }

    public Optional<Address> verify(String envelope, String method, String path) {
        if (envelope == null || envelope.length() > 2048) return Optional.empty();
        try {
            String[] parts = envelope.split("\\.", -1);
            if (parts.length != 2) return Optional.empty();
            byte[] payload = Base64.getUrlDecoder().decode(parts[0]);
            if (!MessageDigest.isEqual(mac(payload), Base64.getUrlDecoder().decode(parts[1]))) return Optional.empty();
            String[] fields = new String(payload, StandardCharsets.UTF_8).split("\n", -1);
            if (fields.length != 6 || !"login-address-v1".equals(fields[0]) || !method.equals(fields[2]) || !path.equals(fields[3])) return Optional.empty();
            long issuedAt = Long.parseLong(fields[1]), now = clock.instant().getEpochSecond();
            if (issuedAt < now - 180 || issuedAt > now + 30 || !numeric(fields[4]) || !validLocalAddresses(fields[5])) return Optional.empty();
            return Optional.of(new Address(fields[4], fields[5]));
        } catch (IllegalArgumentException e) { return Optional.empty(); }
    }

    private byte[] mac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException("Audit address signing unavailable", e); }
    }

    private static boolean numeric(String ip) {
        return ip != null && ip.matches("[0-9a-fA-F:.]{2,45}") && (ip.contains(".") || ip.contains(":"));
    }
    private static boolean validLocalAddresses(String value) {
        if (value == null || value.length() > 512) return false;
        if (value.isEmpty()) return true;
        String[] addresses = value.split(",", -1);
        if (addresses.length > 8) return false;
        for (String address : addresses) if (!numeric(address)) return false;
        return true;
    }
}
