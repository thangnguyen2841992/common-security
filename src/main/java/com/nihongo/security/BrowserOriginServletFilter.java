package com.nihongo.security;
import jakarta.servlet.*;import jakarta.servlet.http.*;import org.springframework.web.filter.OncePerRequestFilter;import java.io.IOException;
public class BrowserOriginServletFilter extends OncePerRequestFilter {
 private final BrowserOriginPolicy policy;private final InternalCredentials internal;private final boolean enabled;
 public BrowserOriginServletFilter(BrowserOriginPolicy policy,InternalCredentials internal,boolean enabled){this.policy=policy;this.internal=internal;this.enabled=enabled;}
 @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws ServletException,IOException{
  if(!enabled||request.getRequestURI().startsWith("/api/auth/internal/")&&internal.matches(request.getHeader(InternalCredentials.HEADER))){chain.doFilter(request,response);return;}
  boolean cookie=false;if(request.getCookies()!=null)for(Cookie c:request.getCookies())if(c.getName().equals("accessToken")||c.getName().equals("refreshToken"))cookie=true;
  String authorization=request.getHeader("Authorization");boolean bearer=authorization!=null&&authorization.startsWith("Bearer ");
  if(!policy.allowed(request.getMethod(),request.getHeader("Origin"),request.getHeader("Referer"),cookie,bearer)){response.setStatus(403);response.setContentType("application/json");response.getWriter().write("{\"message\":\"Nguồn yêu cầu không được phép\"}");return;}chain.doFilter(request,response);
 }
}
