package fixtures.jwtprincipal;

import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The token's subject looked up in the user store on every request (SRC-04): its roles join the token's scopes.
 */
@Configuration
@EnableWebSecurity
class JwtPrincipalConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, JwtAuthenticationConverter converter) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(converter)));
        return http.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(UserDirectory users) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtPrincipalConverter(jwt -> users.load(jwt.getSubject()));
        return converter;
    }
}

@Service
class UserDirectory {

    OAuth2AuthenticatedPrincipal load(String subject) {
        return new DefaultOAuth2AuthenticatedPrincipal(subject, Map.of("sub", subject),
                AuthorityUtils.createAuthorityList(List.of("ROLE_ADMIN")));
    }
}

@RestController
class JwtPrincipalController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
