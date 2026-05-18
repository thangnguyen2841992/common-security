package com.nihongo.security;

import feign.RequestInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class FeignJwtRequestInterceptor
        implements RequestInterceptor {

    @Override
    public void apply(feign.RequestTemplate requestTemplate) {

        var authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuth) {

            String token =
                    jwtAuth.getToken().getTokenValue();

            if (token != null && !token.isBlank()) {

                requestTemplate.header(
                        "Authorization",
                        "Bearer " + token
                );
            }
        }
    }
}
