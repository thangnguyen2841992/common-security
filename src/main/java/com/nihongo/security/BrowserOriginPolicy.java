package com.nihongo.security;
import java.net.URI;import java.util.*;
public final class BrowserOriginPolicy {
 private final Set<String> allowed;
 public BrowserOriginPolicy(String[] origins){Set<String> values=new HashSet<>();for(String origin:origins){String v=canonical(origin);if(v==null||origin.contains("*"))throw new IllegalArgumentException("Use exact HTTP/HTTPS frontend origins");values.add(v);}allowed=Set.copyOf(values);}
 public boolean allowed(String method,String origin,String referer,boolean cookie,boolean bearer){
  if(!Set.of("POST","PUT","PATCH","DELETE").contains(method))return true;
  if(!cookie&&bearer)return true;
  String source=origin!=null?canonical(origin):canonicalReferer(referer);
  return source!=null&&allowed.contains(source);
 }
 private static String canonicalReferer(String value){if(value==null)return null;try{URI u=URI.create(value);return canonical(u.getScheme()+"://"+u.getRawAuthority());}catch(Exception e){return null;}}
 private static String canonical(String value){try{URI u=URI.create(value);if(!Set.of("http","https").contains(u.getScheme())||u.getHost()==null||u.getUserInfo()!=null||u.getRawQuery()!=null||u.getRawFragment()!=null||u.getPath()!=null&&!u.getPath().isEmpty()&&!u.getPath().equals("/"))return null;int port=u.getPort();if(port==80&&u.getScheme().equals("http")||port==443&&u.getScheme().equals("https"))port=-1;return u.getScheme()+"://"+u.getHost().toLowerCase(Locale.ROOT)+(port==-1?"":":"+port);}catch(Exception e){return null;}}
}
