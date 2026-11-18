package fixtures.jwtreactive;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebFlux: the reactive converter, given the servlet one through its adapter; the decoder rewrites claims with a
 * converter of its own.
 */
@Configuration
@EnableWebFluxSecurity
class JwtReactiveConfig {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        http.authorizeExchange(exchange -> exchange.pathMatchers("/admin/**").hasRole("ADMIN")
                        .pathMatchers("/billing/**").hasAuthority("SCOPE_billing")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(converter())));
        return http.build();
    }

    private static ReactiveJwtAuthenticationConverter converter() {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");
        roles.setAuthorityPrefix("ROLE_");
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new ReactiveJwtGrantedAuthoritiesConverterAdapter(roles));
        return converter;
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder() {
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri("https://idp.example.com/jwks")
                .build();
        decoder.setClaimSetConverter(claims -> claims);
        return decoder;
    }
}

@RestController
class JwtReactiveController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/billing/invoices")
    String invoices() {
        return "invoices";
    }
}
