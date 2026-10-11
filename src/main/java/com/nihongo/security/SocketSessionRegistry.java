package com.nihongo.security;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.WebSocketHandlerDecorator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/** Shared-store revocation monitor, batched by session rather than one network call per socket. */
public final class SocketSessionRegistry implements DisposableBean {
 private static final org.slf4j.Logger events=org.slf4j.LoggerFactory.getLogger("nihongo.socket.sessions");
 private record Watched(WebSocketSession socket,RemoteSessionVerifier.SessionRef ref){}
 private final Map<String,Watched> sockets=new ConcurrentHashMap<>();
 private final RemoteSessionVerifier verifier;private final ObjectMapper json=new ObjectMapper();private final ScheduledExecutorService timer;private final boolean enabled;
 public SocketSessionRegistry(RemoteSessionVerifier verifier,Environment env){this(verifier,env.getProperty("security.session-validation.enabled",Boolean.class,true),true);}
 public SocketSessionRegistry(RemoteSessionVerifier verifier,boolean enabled,boolean automatic){this.verifier=verifier;this.enabled=enabled;if(enabled&&automatic){timer=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"socket-session-check");t.setDaemon(true);return t;});timer.scheduleWithFixedDelay(this::checkNow,500,500,TimeUnit.MILLISECONDS);}else timer=null;}
 public WebSocketHandler decorate(WebSocketHandler handler){if(!enabled)return handler;return new WebSocketHandlerDecorator(handler){
  @Override public void afterConnectionEstablished(WebSocketSession socket)throws Exception{
   if(!(socket.getPrincipal() instanceof JwtAuthenticationToken auth)||!"access".equals(auth.getToken().getClaimAsString("type"))||auth.getToken().getExpiresAt()==null||!auth.getToken().getExpiresAt().isAfter(Instant.now())){events.warn("event=rejected socketId={} reason=invalid-token",socket.getId());socket.close(CloseStatus.POLICY_VIOLATION);return;}
   var jwt=auth.getToken();var ref=new RemoteSessionVerifier.SessionRef(jwt.getSubject(),jwt.getClaimAsString("sessionId"),jwt.getClaimAsStringList("roles"));sockets.put(socket.getId(),new Watched(socket,ref));try{super.afterConnectionEstablished(socket);events.info("event=connected socketId={} userId={} active={}",socket.getId(),jwt.getSubject(),sockets.size());}catch(Exception e){sockets.remove(socket.getId());events.warn("event=connect-failed socketId={} failure={}",socket.getId(),e.getClass().getSimpleName());throw e;}
  }
  @Override public void afterConnectionClosed(WebSocketSession socket,CloseStatus status)throws Exception{if(sockets.remove(socket.getId())!=null)events.info("event=disconnected socketId={} code={} active={}",socket.getId(),status.getCode(),sockets.size());super.afterConnectionClosed(socket,status);}
 };}
 public void checkNow(){
  List<Watched> snapshot=new ArrayList<>(sockets.values());if(snapshot.isEmpty())return;
  try{var distinct=new LinkedHashMap<String,RemoteSessionVerifier.SessionRef>();snapshot.forEach(w->distinct.put(w.ref().userId()+":"+w.ref().sessionId(),w.ref()));var refs=new ArrayList<>(distinct.values());Set<String> invalid=new HashSet<>();
   for(int i=0;i<refs.size();i+=100){String response=verifier.checkBatch(json.writeValueAsString(refs.subList(i,Math.min(i+100,refs.size()))));invalid.addAll(json.readValue(response,json.getTypeFactory().constructCollectionType(List.class,String.class)));}
   for(var w:snapshot)if(invalid.contains(w.ref().userId()+":"+w.ref().sessionId()))close(w,"session-invalid");
  }catch(Exception unavailable){events.warn("event=session-check-failed connections={} failure={}",snapshot.size(),unavailable.getClass().getSimpleName());for(var w:snapshot)close(w,"auth-unavailable");}
 }
 private void close(Watched w,String reason){if(!sockets.remove(w.socket().getId(),w))return;events.info("event=closed socketId={} reason={} active={}",w.socket().getId(),reason,sockets.size());try{w.socket().close(CloseStatus.POLICY_VIOLATION);}catch(Exception unavailable){events.debug("event=close-transport-failed socketId={} failure={}",w.socket().getId(),unavailable.getClass().getSimpleName());}}
 public org.springframework.messaging.support.ChannelInterceptor outboundGuard(){return new org.springframework.messaging.support.ChannelInterceptor(){@Override public org.springframework.messaging.Message<?> preSend(org.springframework.messaging.Message<?> message,org.springframework.messaging.MessageChannel channel){Object id=message.getHeaders().get(org.springframework.messaging.simp.SimpMessageHeaderAccessor.SESSION_ID_HEADER);return enabled&&id instanceof String sid&&!sockets.containsKey(sid)?null:message;}};}
 @Override public void destroy(){if(timer!=null)timer.shutdownNow();for(var w:new ArrayList<>(sockets.values()))close(w,"shutdown");}
}
