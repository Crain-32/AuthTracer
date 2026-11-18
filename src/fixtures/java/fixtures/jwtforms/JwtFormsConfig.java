package fixtures.jwtforms;

import java.util.Collection;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Converters built the ways applications spread them out: returned by a helper typed as a Converter, configured in
 * another method, held in a field, handed to an authentication provider, with a prefix from the environment.
 */
@Configuration
@EnableWebSecurity
class JwtFormsConfig {

    private final Converter<Jwt, Collection<GrantedAuthority>> partnerAuthorities = new JwtGrantedAuthoritiesConverter();

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("TEAM"))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new DelegatingJwtGrantedAuthoritiesConverter(scopes(), teams(),
                regions()));
        return converter;
    }

    private Converter<Jwt, Collection<GrantedAuthority>> scopes() {
        return new JwtGrantedAuthoritiesConverter();
    }

    private static JwtGrantedAuthoritiesConverter teams() {
        JwtGrantedAuthoritiesConverter teams = new JwtGrantedAuthoritiesConverter();
        configure(teams);
        return teams;
    }

    private static void configure(JwtGrantedAuthoritiesConverter teams) {
        teams.setAuthoritiesClaimName("teams");
        teams.setAuthorityPrefix("TEAM_");
    }

    private static JwtGrantedAuthoritiesConverter regions() {
        JwtGrantedAuthoritiesConverter regions = new JwtGrantedAuthoritiesConverter();
        regions.setAuthoritiesClaimName("regions");
        regions.setAuthorityPrefix(System.getenv("REGION_PREFIX"));
        return regions;
    }

    @Bean
    JwtAuthenticationProvider partnerProvider(JwtDecoder decoder) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(partnerAuthorities);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(converter);
        return provider;
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/jwks").build();
        decoder.setClaimSetConverter(MappedJwtClaimSetConverter.withDefaults(Collections.singletonMap("teams",
                teams -> teams)));
        return decoder;
    }
}

@RestController
class JwtFormsController {

    @GetMapping("/teams")
    String teams() {
        return "teams";
    }
}
