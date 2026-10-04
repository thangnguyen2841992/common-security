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

    @Bean
    public Request.Options feignRequestOptions(
            @Value("${services.http.connect-timeout-ms:3000}") long connectTimeout,
            @Value("${services.http.read-timeout-ms:10000}") long readTimeout) {
        return new Request.Options(connectTimeout, TimeUnit.MILLISECONDS, readTimeout, TimeUnit.MILLISECONDS, true);
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
