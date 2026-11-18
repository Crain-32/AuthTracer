package fixtures.soapnoboot;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.transport.http.support.AbstractAnnotationConfigMessageDispatcherServletInitializer;

/**
 * Decision 0080: Spring Web Services without Spring Boot, its dispatcher servlet registered by a
 * WebApplicationInitializer at the paths it overrides.
 */
@Configuration
@EnableWs
@EnableWebSecurity
class SoapNoBootConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.requestMatchers("/ws/**").hasRole("PARTNER")
                .anyRequest().denyAll()).build();
    }
}

class SoapInitializer extends AbstractAnnotationConfigMessageDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class<?>[] {SoapNoBootConfig.class};
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[0];
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] {"/ws/*"};
    }
}

@Endpoint
class OrderEndpoint {

    @PayloadRoot(namespace = "http://example.com/orders", localPart = "orderRequest")
    public void order(@RequestPayload Object request) {
    }
}
