package com.nihongo.security;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.web.socket.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.time.Instant;
import java.security.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityHardeningTest {
 @AfterEach void cleanup(){SecurityContextHolder.clearContext();}
 @TempDir Path temporary;
 private InternalCredentials credentials(){return new InternalCredentials(new MockEnvironment().withProperty("security.internal.key",Base64.getEncoder().encodeToString(new byte[32])));}
 @Test void cookieAndLoginRequestsRequireAnExactTrustedSource(){
  var p=new BrowserOriginPolicy(new String[]{"http://localhost:5173","https://learn.example.com"});
  assertTrue(p.allowed("POST","http://localhost:5173",null,true,false));assertTrue(p.allowed("POST",null,"https://learn.example.com/page",true,false));assertTrue(p.allowed("POST",null,null,false,true));
  for(String origin:new String[]{"https://evil.example.com","null","http://localhost:5173.evil","http://user@localhost:5173"})assertFalse(p.allowed("POST",origin,"http://localhost:5173/page",true,true));
  assertFalse(p.allowed("POST",null,null,false,false));assertFalse(p.allowed("DELETE",null,null,true,true));assertTrue(p.allowed("GET",null,null,true,false));
  assertThrows(IllegalArgumentException.class,()->new BrowserOriginPolicy(new String[]{"*"}));
 }
 @Test void servletOriginGuardRejectsMissingOriginBeforeSideEffects()throws Exception{
  var f=new BrowserOriginServletFilter(new BrowserOriginPolicy(new String[]{"http://localhost:5173"}),credentials(),true);var chain=mock(jakarta.servlet.FilterChain.class);
  var request=new MockHttpServletRequest("POST","/api/auth/login");var response=new MockHttpServletResponse();f.doFilter(request,response,chain);assertEquals(403,response.getStatus());verifyNoInteractions(chain);
  request=new MockHttpServletRequest("POST","/api/nihongo-user/subscriptions");request.setCookies(new jakarta.servlet.http.Cookie("accessToken","token"));request.addHeader("Origin","http://localhost:5173");request.addHeader("Authorization","Bearer token");response=new MockHttpServletResponse();f.doFilter(request,response,chain);verify(chain).doFilter(request,response);
 }
 @Test void directBackendChecksRevocationAndDistinguishesOutage()throws Exception{
  var verifier=mock(RemoteSessionVerifier.class);var f=new ServletSessionValidationFilter(verifier,true);var chain=mock(jakarta.servlet.FilterChain.class);
  var token=Jwt.withTokenValue("verified").header("alg","RS256").subject("owner").claim("sessionId","sid").claim("roles",List.of("USER")).claim("type","access").expiresAt(Instant.now().plusSeconds(60)).build();SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(token));
  when(verifier.status(token)).thenReturn(401);var response=new MockHttpServletResponse();f.doFilter(new MockHttpServletRequest("GET","/api/private"),response,chain);assertEquals(401,response.getStatus());assertEquals("session-invalid",response.getHeader("X-Auth-Failure"));verifyNoInteractions(chain);
  when(verifier.status(token)).thenReturn(503);response=new MockHttpServletResponse();f.doFilter(new MockHttpServletRequest("GET","/api/private"),response,chain);assertEquals(503,response.getStatus());verifyNoInteractions(chain);
  when(verifier.status(token)).thenReturn(204);f.doFilter(new MockHttpServletRequest("GET","/api/private"),new MockHttpServletResponse(),chain);verify(chain).doFilter(any(),any());
 }
 String token(KeyPair pair,String issuer,String audience,String type,String sid)throws Exception{
  var claims=new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject("owner").claim("roles",List.of("STAFF")).claim("type",type).claim("sessionId",sid).expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
  var token=new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),claims);token.sign(new RSASSASigner(pair.getPrivate()));return token.serialize();
 }
 @Test void rsaDecoderRequiresCorrectIssuerAudienceTypeAndSession()throws Exception{
  var g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);var pair=g.generateKeyPair();Path file=temporary.resolve("public.pem");Files.writeString(file,"-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(pair.getPublic().getEncoded())+"\n-----END PUBLIC KEY-----");
  var env=new MockEnvironment().withProperty("security.jwt.public-key-path",file.toString()).withProperty("security.jwt.issuer","test-auth").withProperty("security.jwt.audience","test-api");var decoder=SecurityJwtDecoders.servlet(env);
  assertEquals("owner",decoder.decode(token(pair,"test-auth","test-api","access","sid")).getSubject());
  assertThrows(JwtException.class,()->decoder.decode(token(pair,"wrong","test-api","access","sid")));assertThrows(JwtException.class,()->decoder.decode(token(pair,"test-auth","wrong","access","sid")));assertThrows(JwtException.class,()->decoder.decode(token(pair,"test-auth","test-api","refresh","sid")));assertThrows(JwtException.class,()->decoder.decode(token(pair,"test-auth","test-api","access",null)));assertThrows(JwtException.class,()->decoder.decode(token(pair,"test-auth","test-api","access","")));
  var other=g.generateKeyPair();assertThrows(JwtException.class,()->decoder.decode(token(other,"test-auth","test-api","access","sid")));
 }
 @Test void revokedSocketsAreClosedAndOutboundMessagesBlockedEvenWhenCloseFails()throws Exception{
  var verifier=mock(RemoteSessionVerifier.class);when(verifier.checkBatch(anyString())).thenReturn("[\"owner:sid\"]");
  try(var ignored=new AutoCloseable(){public void close(){}}){var registry=new SocketSessionRegistry(verifier,true,false);var socket=mock(WebSocketSession.class);when(socket.getId()).thenReturn("ws-1");when(socket.getPrincipal()).thenReturn(new JwtAuthenticationToken(Jwt.withTokenValue("verified").header("alg","RS256").subject("owner").claim("sessionId","sid").claim("roles",List.of("USER")).claim("type","access").expiresAt(Instant.now().plusSeconds(60)).build()));
   var handler=registry.decorate(mock(WebSocketHandler.class));handler.afterConnectionEstablished(socket);var message=MessageBuilder.withPayload("notice").setHeader("simpSessionId","ws-1").build();assertSame(message,registry.outboundGuard().preSend(message,null));doThrow(new java.io.IOException("closed transport")).when(socket).close(any());registry.checkNow();verify(socket).close(CloseStatus.POLICY_VIOLATION);assertNull(registry.outboundGuard().preSend(message,null));registry.destroy();
  }
 }
 @Test void productionRejectsWeakerFlagsAndHttpOrigins(){var env=new MockEnvironment();env.addActiveProfile("production");env.setProperty("FRONTEND_ORIGIN","https://learn.example.com");env.setProperty("security.jwt.public-key-path","/secrets/public.pem");env.setProperty("security.internal.key-path","/secrets/internal.key");ProductionSecurityPolicy.verify(env);env.setProperty("security.session-validation.enabled","false");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));env.setProperty("security.session-validation.enabled","true");env.setProperty("FRONTEND_ORIGIN","http://learn.example.com");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));}
 @Test void productionRejectsPlaintextRemoteSecurityAndDatabaseConnections(){
  var env=new MockEnvironment().withProperty("FRONTEND_ORIGIN","https://learn.example.com").withProperty("security.jwt.public-key-path","/secrets/public.pem").withProperty("security.internal.key-path","/secrets/internal.key");env.addActiveProfile("production");
  env.setProperty("auth.session-validation-url","http://10.0.0.2:8081/api/auth/session/validate");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));env.setProperty("auth.session-validation-url","https://auth.example.com/api/auth/session/validate");ProductionSecurityPolicy.verify(env);
  env.setProperty("spring.datasource.url","jdbc:mysql://db.example.com:3306/nihongo?useSSL=false");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));env.setProperty("spring.datasource.url","jdbc:mysql://db.example.com:3306/nihongo?sslMode=VERIFY_IDENTITY&serverTimezone=UTC");ProductionSecurityPolicy.verify(env);
  env.setProperty("spring.application.name","gateway-service");env.setProperty("server.forward-headers-strategy","framework");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));env.setProperty("server.forward-headers-strategy","none");ProductionSecurityPolicy.verify(env);
 }
 @Test void productionAuthRequiresSecureCookiesAndSigningAndEncryptionKeys(){
  var env=new MockEnvironment().withProperty("spring.application.name","user-service").withProperty("FRONTEND_URL","https://learn.example.com").withProperty("FRONTEND_ORIGIN","https://learn.example.com").withProperty("security.jwt.public-key-path","/secrets/public.pem").withProperty("security.internal.key-path","/secrets/internal.key");env.addActiveProfile("production");
  assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));env.setProperty("security.jwt.private-key-path","/secrets/private.pem");env.setProperty("security.session.encryption-key-path","/secrets/session.key");ProductionSecurityPolicy.verify(env);env.setProperty("COOKIE_SECURE","false");assertThrows(IllegalStateException.class,()->ProductionSecurityPolicy.verify(env));
 }
}
