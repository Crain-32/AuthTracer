package fixtures.jwtauthorities;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * An identity provider that puts roles in a comma-separated {@code groups} claim: the converter reads that claim
 * only, with the {@code ROLE_} prefix. The reports rule still asks for a scope, which no token carries any more.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class JwtAuthoritiesConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, JwtAuthenticationConverter converter) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/reports/**").hasAuthority("SCOPE_reports.read")
                        .requestMatchers("/audit/**").hasAnyAuthority("SCOPE_audit", "ROLE_AUDITOR")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(converter)));
        return http.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter groups = new JwtGrantedAuthoritiesConverter();
        groups.setAuthoritiesClaimName("groups");
        groups.setAuthorityPrefix("ROLE_");
        groups.setAuthoritiesClaimDelimiter(",");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(groups);
        return converter;
    }
}

@RestController
class JwtAuthoritiesController {

    private final ExportService exports;

    JwtAuthoritiesController(ExportService exports) {
        this.exports = exports;
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }

    @GetMapping("/audit/log")
    String log() {
        return "log";
    }

    @GetMapping("/exports")
    String exports() {
        return exports.export();
    }
}

@Service
class ExportService {

    @PreAuthorize("hasAuthority('SCOPE_exports') and hasRole('EXPORTER')")
    String export() {
        return "export";
    }
}
