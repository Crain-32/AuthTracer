package fixtures.jwtexpressions;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ExpressionJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Keycloak's realm roles, picked out by a SpEL expression, next to the default scopes: a delegating converter given a
 * list of both.
 */
@Configuration
@EnableWebSecurity
class JwtExpressionsConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/orders/**").hasAuthority("SCOPE_orders")
                        .requestMatchers("/legacy/**").hasAuthority("GROUP_legacy")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(converter())));
        return http.build();
    }

    private static JwtAuthenticationConverter converter() {
        ExpressionJwtGrantedAuthoritiesConverter realmRoles = new ExpressionJwtGrantedAuthoritiesConverter(
                new SpelExpressionParser().parseExpression("[realm_access][roles]"));
        realmRoles.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new DelegatingJwtGrantedAuthoritiesConverter(
                List.of(new JwtGrantedAuthoritiesConverter(), realmRoles)));
        return converter;
    }
}

@RestController
class JwtExpressionsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/orders/open")
    String orders() {
        return "orders";
    }

    @GetMapping("/legacy/report")
    String report() {
        return "report";
    }
}
