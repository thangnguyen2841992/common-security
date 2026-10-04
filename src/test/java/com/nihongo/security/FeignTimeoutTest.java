package com.nihongo.security;

import feign.Request;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;

class FeignTimeoutTest {
    @Test
    void internalCallsHaveBoundedTimeoutsAndAllowDeploymentOverrides() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("test", Map.of(
                    "services.http.connect-timeout-ms", "1200", "services.http.read-timeout-ms", "4500")));
            context.register(CommonSecurityConfig.class);
            context.refresh();
            var options = context.getBean(Request.Options.class);
            assertEquals(1200, options.connectTimeoutMillis());
            assertEquals(4500, options.readTimeoutMillis());
        }
    }
}
