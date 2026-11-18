package fixtures.multitenant;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * One tenant sends JWTs, the other opaque tokens (spring-security-samples' multi-tenancy).
 */
@Configuration
@EnableWebSecurity
@RestController
class MultiTenantApplication {

    @Bean
    SecurityFilterChain api(HttpSecurity http, AuthenticationManagerResolver<HttpServletRequest> tenants)
            throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasAuthority("SCOPE_message:read"))
                .oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(tenants));
        return http.build();
    }

    @Bean
    AuthenticationManagerResolver<HttpServletRequest> tenants(JwtDecoder jwtDecoder,
            OpaqueTokenIntrospector introspector) {
        Map<String, AuthenticationManager> managers = Map.of(
                "tenantOne", new ProviderManager(new JwtAuthenticationProvider(jwtDecoder)),
                "tenantTwo", new ProviderManager(new OpaqueTokenAuthenticationProvider(introspector)));
        return request -> managers.get(request.getRequestURI().split("/")[1]);
    }

    @GetMapping("/{tenant}/message")
    String message() {
        return "hello";
    }
}
