package com.nihongo.security;
import org.springframework.security.oauth2.jwt.Jwt;import org.springframework.core.env.Environment;import java.net.*;import java.net.http.*;import java.time.Duration;import java.util.*;import java.util.concurrent.ConcurrentHashMap;import java.util.concurrent.atomic.AtomicInteger;
public final class RemoteSessionVerifier {
 private final HttpClient client;private final URI validate,batch;private final InternalCredentials internal;
 // Short positive cache, same policy as the gateway: logout/revocation still propagates within the TTL.
 private final long cacheTtlMillis;private final int maxCacheEntries;
 private final ConcurrentHashMap<String,Long> validSessions=new ConcurrentHashMap<>();private final AtomicInteger requests=new AtomicInteger();
 public RemoteSessionVerifier(Environment env,InternalCredentials internal){this.internal=internal;client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).followRedirects(HttpClient.Redirect.NEVER).build();validate=URI.create(env.getProperty("auth.session-validation-url","http://127.0.0.1:8081/api/auth/session/validate"));batch=URI.create(env.getProperty("auth.session-batch-url","http://127.0.0.1:8081/api/auth/internal/sessions/check"));cacheTtlMillis=Math.max(0,env.getProperty("auth.session-cache-ttl",Long.class,5000L));maxCacheEntries=Math.max(100,env.getProperty("auth.session-cache-max-entries",Integer.class,20000));}
 public int status(Jwt jwt){
  String key=cacheKey(jwt);long now=System.currentTimeMillis();
  if(key!=null&&cacheTtlMillis>0){Long until=validSessions.get(key);if(until!=null&&until>now)return 204;if(until!=null)validSessions.remove(key,until);if((requests.incrementAndGet()&255)==0)validSessions.entrySet().removeIf(e->e.getValue()<=now);}
  int status=fetch(jwt);
  if(key!=null&&cacheTtlMillis>0&&status>=200&&status<300)remember(key,jwt,now);
  return status;
 }
 private int fetch(Jwt jwt){try{return client.send(HttpRequest.newBuilder(validate).timeout(Duration.ofSeconds(2)).header("Authorization","Bearer "+jwt.getTokenValue()).header(InternalCredentials.HEADER,internal.value()).GET().build(),HttpResponse.BodyHandlers.discarding()).statusCode();}catch(InterruptedException e){Thread.currentThread().interrupt();return 503;}catch(Exception e){return 503;}}
 private static String cacheKey(Jwt jwt){String sid=jwt.getClaimAsString("sessionId");if(jwt.getSubject()==null||sid==null||!"access".equals(jwt.getClaimAsString("type")))return null;return jwt.getSubject()+':'+sid+':'+jwt.getClaims().get("roles");}
 private void remember(String key,Jwt jwt,long now){
  if(validSessions.size()>=maxCacheEntries){validSessions.entrySet().removeIf(e->e.getValue()<=now);if(validSessions.size()>=maxCacheEntries)return;}
  long expiry=jwt.getExpiresAt()==null?Long.MAX_VALUE:jwt.getExpiresAt().toEpochMilli();validSessions.put(key,Math.min(expiry,now+cacheTtlMillis));
 }
 public record SessionRef(String userId,String sessionId,List<String> roles){}
 public String checkBatch(String json){try{var r=client.send(HttpRequest.newBuilder(batch).timeout(Duration.ofSeconds(2)).header(InternalCredentials.HEADER,internal.value()).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(json)).build(),HttpResponse.BodyHandlers.ofString());if(r.statusCode()!=200)throw new IllegalStateException("Session verification unavailable");return r.body();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("Session verification unavailable",e);}catch(Exception e){throw new IllegalStateException("Session verification unavailable",e);}}
}
