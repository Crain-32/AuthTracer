package fixtures.jwtcustomconverter;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.core.annotation.Order;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authorities a converter of the application's computes, as the Keycloak guides write one; and a partner chain whose
 * DSL is given a lambda.
 */
@Configuration
@EnableWebSecurity
class JwtCustomConverterConfig {

    @Bean
    @Order(1)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatcher("/partner/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("PARTNER"))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.jwtAuthenticationConverter(
                        token -> new JwtAuthenticationToken(token, List.of(new SimpleGrantedAuthority("ROLE_PARTNER"))))));
        return http.build();
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }
}

/**
 * {@code realm_access.roles}, each with ROLE_.
 */
class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realm = jwt.getClaimAsMap("realm_access");
        return ((List<String>) realm.get("roles")).stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role)).toList();
    }
}

@RestController
class JwtCustomConverterController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/partner/orders")
    String orders() {
        return "orders";
    }
}
