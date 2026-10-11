package com.nihongo.security;
import org.springframework.core.env.*;import java.net.URI;
public final class ProductionSecurityPolicy {
 private ProductionSecurityPolicy(){}
 public static void verify(Environment env){if(!env.acceptsProfiles(Profiles.of("production","prod")))return;
  if(!"rsa".equals(env.getProperty("security.jwt.mode","rsa"))||env.getProperty("security.jwt.allow-legacy-hmac",Boolean.class,false)||!env.getProperty("security.jwt.validate-claims",Boolean.class,true)||!env.getProperty("security.session-validation.enabled",Boolean.class,true)||!env.getProperty("security.origin-check.enabled",Boolean.class,true))throw new IllegalStateException("Production cannot disable JWT, session or browser-origin protection");
  String origins=env.getProperty("FRONTEND_ORIGIN","");if(origins.isBlank())throw new IllegalStateException("Configure production HTTPS frontend origins");for(String origin:origins.split(","))if(!"https".equals(URI.create(origin.trim()).getScheme()))throw new IllegalStateException("Production frontend origins must use HTTPS");
  if(env.getProperty("security.jwt.public-key-path","").isBlank())throw new IllegalStateException("Mount the production JWT public key explicitly");
  if(env.getProperty("security.internal.key","").isBlank()&&env.getProperty("security.internal.key-path","").isBlank())throw new IllegalStateException("Provision production internal credentials explicitly");
  if(java.util.List.of("user-service","notification-service").contains(env.getProperty("spring.application.name",""))&&!"https".equals(URI.create(env.getProperty("FRONTEND_URL","")).getScheme()))throw new IllegalStateException("Configure a production HTTPS FRONTEND_URL for authentication and email links");
  if("gateway-service".equals(env.getProperty("spring.application.name"))&&!"none".equalsIgnoreCase(env.getProperty("server.forward-headers-strategy","none")))throw new IllegalStateException("Gateway must preserve the transport peer for trusted-proxy validation");
  verifyInternalUrl(env.getProperty("auth.session-validation-url",env.getProperty("AUTH_SESSION_VALIDATION_URL","http://127.0.0.1:8081/api/auth/session/validate")));
  verifyInternalUrl(env.getProperty("auth.session-batch-url","http://127.0.0.1:8081/api/auth/internal/sessions/check"));
  verifyInternalUrl(env.getProperty("auth.rate-limit-url","http://127.0.0.1:8081/api/auth/internal/rate-limit"));
  String database=env.getProperty("spring.datasource.url","");
  if(database.startsWith("jdbc:mysql:")&&!database.matches("(?i).*([?&])sslMode=VERIFY_IDENTITY(&.*)?$"))throw new IllegalStateException("Production MySQL connections require sslMode=VERIFY_IDENTITY");
  if("user-service".equals(env.getProperty("spring.application.name"))){if(!env.getProperty("COOKIE_SECURE",Boolean.class,true))throw new IllegalStateException("Production cookies must be Secure");if(env.getProperty("security.jwt.private-key-path","").isBlank())throw new IllegalStateException("Mount the signing key only on auth-service");if(env.getProperty("security.session.encryption-key","").isBlank()&&env.getProperty("security.session.encryption-key-path","").isBlank())throw new IllegalStateException("Provision the production session encryption key");}
 }
 private static void verifyInternalUrl(String value){URI uri=URI.create(value);String host=uri.getHost();if(uri.getUserInfo()!=null||host==null||!("https".equals(uri.getScheme())||("http".equals(uri.getScheme())&&java.util.List.of("localhost","127.0.0.1","[::1]","::1").contains(host))))throw new IllegalStateException("Internal security credentials require HTTPS or a loopback connection");}
}
