package com.nihongo.security;
import org.springframework.security.oauth2.core.*;import org.springframework.security.oauth2.jwt.*;import java.util.List;
public final class AccessTokenValidators {
 private AccessTokenValidators(){}
 public static OAuth2TokenValidator<Jwt> create(String issuer,String audience,boolean validateClaims){
  var timestamps=JwtValidators.createDefault();
  if(!validateClaims)return timestamps;
  return new DelegatingOAuth2TokenValidator<>(timestamps,new JwtIssuerValidator(issuer),jwt->{
   boolean valid;
   try {
   List<String> roles=jwt.getClaimAsStringList("roles");
   String sid=jwt.getClaimAsString("sessionId");
   valid=jwt.getAudience()!=null&&jwt.getAudience().contains(audience)&&"access".equals(jwt.getClaimAsString("type"))
    &&jwt.getExpiresAt()!=null&&jwt.getSubject()!=null&&!jwt.getSubject().isBlank()&&sid!=null&&!sid.isBlank()
    &&roles!=null&&roles.size()==1&&List.of("USER","STAFF","ADMIN").contains(roles.get(0));
   } catch (RuntimeException malformed) { valid=false; }
   return valid?OAuth2TokenValidatorResult.success():OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Invalid access token claims",null));
  });
 }
}
