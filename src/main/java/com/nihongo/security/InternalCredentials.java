package com.nihongo.security;
import org.springframework.core.env.Environment;import java.nio.charset.StandardCharsets;import java.security.MessageDigest;import java.util.Base64;
public final class InternalCredentials {
 public static final String HEADER="X-Nihongo-Internal";
 private final String value;
 public InternalCredentials(Environment env){value=Base64.getEncoder().encodeToString(SecurityKeyFiles.secret(env.getProperty("security.internal.key",""),env.getProperty("security.internal.key-path",".local/security/internal.key")));}
 public String value(){return value;}
 public boolean matches(String candidate){return candidate!=null&&candidate.length()<256&&MessageDigest.isEqual(value.getBytes(StandardCharsets.US_ASCII),candidate.getBytes(StandardCharsets.US_ASCII));}
}
