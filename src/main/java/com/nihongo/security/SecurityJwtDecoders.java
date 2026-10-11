package com.nihongo.security;
import org.springframework.core.env.Environment;import org.springframework.security.oauth2.jwt.*;import org.springframework.security.oauth2.jose.jws.*;import javax.crypto.spec.SecretKeySpec;import java.util.Base64;
public final class SecurityJwtDecoders {
 private SecurityJwtDecoders(){}
 public static JwtDecoder servlet(Environment env){
  NimbusJwtDecoder decoder;
  if(legacy(env))decoder=NimbusJwtDecoder.withSecretKey(new SecretKeySpec(Base64.getDecoder().decode(env.getRequiredProperty("jwt.secret")),"HmacSHA256")).macAlgorithm(MacAlgorithm.HS256).build();
  else decoder=NimbusJwtDecoder.withPublicKey(SecurityKeyFiles.publicKey(env.getProperty("security.jwt.public-key-path",".local/security/jwt-public.pem"))).signatureAlgorithm(SignatureAlgorithm.RS256).build();
  decoder.setJwtValidator(AccessTokenValidators.create(env.getProperty("security.jwt.issuer","nihongo-auth"),env.getProperty("security.jwt.audience","nihongo-api"),env.getProperty("security.jwt.validate-claims",Boolean.class,true)));
  return decoder;
 }
 public static ReactiveJwtDecoder reactive(Environment env){
  NimbusReactiveJwtDecoder decoder;
  if(legacy(env))decoder=NimbusReactiveJwtDecoder.withSecretKey(new SecretKeySpec(Base64.getDecoder().decode(env.getRequiredProperty("jwt.secret")),"HmacSHA256")).macAlgorithm(MacAlgorithm.HS256).build();
  else decoder=NimbusReactiveJwtDecoder.withPublicKey(SecurityKeyFiles.publicKey(env.getProperty("security.jwt.public-key-path",".local/security/jwt-public.pem"))).signatureAlgorithm(SignatureAlgorithm.RS256).build();
  decoder.setJwtValidator(AccessTokenValidators.create(env.getProperty("security.jwt.issuer","nihongo-auth"),env.getProperty("security.jwt.audience","nihongo-api"),env.getProperty("security.jwt.validate-claims",Boolean.class,true)));return decoder;
 }
 public static boolean legacy(Environment env){String mode=env.getProperty("security.jwt.mode","rsa");if(!"rsa".equals(mode)&&!"legacy".equals(mode))throw new IllegalStateException("Unknown JWT mode");boolean legacy="legacy".equals(mode);if(legacy&&!env.getProperty("security.jwt.allow-legacy-hmac",Boolean.class,false))throw new IllegalStateException("Legacy JWT mode must be explicitly enabled for migration/testing");if(!legacy&&!env.getProperty("security.jwt.validate-claims",Boolean.class,true))throw new IllegalStateException("RSA access tokens require claim validation");return legacy;}
}
