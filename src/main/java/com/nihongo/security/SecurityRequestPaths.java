package com.nihongo.security;
import java.net.URI;import java.util.Locale;
public final class SecurityRequestPaths {
 private SecurityRequestPaths(){}
 public static String canonical(URI uri){String raw=uri.getRawPath(),path=uri.getPath();if(raw==null||path==null)throw new IllegalArgumentException("Invalid request path");String lower=raw.toLowerCase(Locale.ROOT);if(path.contains("\\")||path.contains(";")||path.contains("/../")||path.endsWith("/..")||path.contains("/./")||path.endsWith("/.")||path.chars().anyMatch(c->c<32||c==127)||lower.contains("%2f")||lower.contains("%5c")||lower.contains("%25"))throw new IllegalArgumentException("Ambiguous request path");return path;}
}
