package com.nihongo.security;

import feign.RequestInterceptor;
import feign.Request;
import org.springframework.beans.factory.annotation.Value;
import java.util.concurrent.TimeUnit;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@Configuration(proxyBeanMethods = false)
public class CommonSecurityConfig {
    @Bean public org.springframework.beans.factory.InitializingBean productionSecurityPolicy(org.springframework.core.env.Environment env){return ()->ProductionSecurityPolicy.verify(env);}
    @Bean public InternalCredentials internalCredentials(org.springframework.core.env.Environment env){return new InternalCredentials(env);}
    @Bean public BrowserOriginPolicy browserOriginPolicy(@Value("${FRONTEND_ORIGIN:http://localhost:5173}") String[] origins){return new BrowserOriginPolicy(origins);}
    @Bean public RemoteSessionVerifier remoteSessionVerifier(org.springframework.core.env.Environment env,InternalCredentials credentials){return new RemoteSessionVerifier(env,credentials);}
    @Bean public SocketSessionRegistry socketSessionRegistry(RemoteSessionVerifier verifier,org.springframework.core.env.Environment env){return new SocketSessionRegistry(verifier,env);}

    @Bean
    public Request.Options feignRequestOptions(
            @Value("${services.http.connect-timeout-ms:3000}") long connectTimeout,
            @Value("${services.http.read-timeout-ms:10000}") long readTimeout) {
        return new Request.Options(connectTimeout, TimeUnit.MILLISECONDS, readTimeout, TimeUnit.MILLISECONDS, false);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {

        JwtAuthenticationConverter converter =
                new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(
                new JwtRoleConverter()
        );

        return converter;
    }

    @Bean
    public RequestInterceptor requestInterceptor() {
        return new FeignJwtRequestInterceptor();
    }
}
