package dev.crain.employeeservice.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtAuthoritiesTests {

    @Test
    void mapsScopesAndRolesClaims() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("admin")
                .claim("scope", "openid employees.read")
                .claim("roles", List.of("USER", "ADMIN"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        var authorities = new SecurityConfig().jwtAuthenticationConverter().convert(jwt).getAuthorities();

        // Spring Security 7 also records the authentication factor as an authority.
        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_employees.read", "ROLE_USER", "ROLE_ADMIN",
                        "FACTOR_BEARER");
    }
}
