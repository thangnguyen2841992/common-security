package com.nihongo.security;
import jakarta.servlet.*;import jakarta.servlet.http.*;import org.springframework.web.filter.OncePerRequestFilter;import org.springframework.security.core.context.SecurityContextHolder;import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;import java.io.IOException;
public class ServletSessionValidationFilter extends OncePerRequestFilter {
 private final RemoteSessionVerifier verifier;private final boolean enabled;
 public ServletSessionValidationFilter(RemoteSessionVerifier verifier,boolean enabled){this.verifier=verifier;this.enabled=enabled;}
 @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws ServletException,IOException{
  var auth=SecurityContextHolder.getContext().getAuthentication();if(!enabled||!(auth instanceof JwtAuthenticationToken jwt)){chain.doFilter(request,response);return;}
  int status=verifier.status(jwt.getToken());if(status>=200&&status<300){chain.doFilter(request,response);return;}
  response.setStatus(status==401||status==403?401:503);if(response.getStatus()==401)response.setHeader("X-Auth-Failure","session-invalid");response.setContentType("application/json");response.getWriter().write(response.getStatus()==401?"{\"message\":\"Phiên đăng nhập đã hết hiệu lực\"}":"{\"message\":\"Dịch vụ xác thực tạm thời gián đoạn\"}");
 }
}
