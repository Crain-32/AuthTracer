package fixtures.jwtvalidatorforms;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OAUTH-06 and SRC-02: a decoder whose validators are built one by one and combined from a list (an issuer, two
 * audience validators, one of them from the environment, the typ header, a tenant claim, an audience test AuthTracer
 * can't read, the timestamps), a second decoder for access tokens of a client; and the converter the DSL is given as
 * a bean the chain method is handed, its claim name from the environment.
 */
@Configuration
@EnableWebSecurity
class JwtValidatorFormsConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> tokens)
            throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt
                        .jwtAuthenticationConverter(tokens)));
        return http.build();
    }

    @Bean
    Converter<Jwt, AbstractAuthenticationToken> tokens(Environment environment) {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName(environment.getProperty("jwt.roles-claim"));
        roles.setAuthorityPrefix("ROLE_");
        roles.setAuthoritiesClaimDelimiter(" ");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);
        return converter;
    }

    @Bean
    JwtDecoder jwtDecoder(Environment environment) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/jwks").build();
        String partner = environment.getProperty("jwt.partner-audience");
        List<OAuth2TokenValidator<Jwt>> validators = List.of(
                new JwtIssuerValidator("https://idp.example.com"),
                new JwtAudienceValidator("orders-api"),
                new JwtAudienceValidator(partner),
                JwtTypeValidator.jwt(),
                new JwtClaimValidator<String>("tenant", "acme"::equals),
                new JwtClaimValidator<List<String>>("aud", JwtValidatorFormsConfig::trusted),
                new JwtTimestampValidator());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    @Bean
    JwtDecoder clientDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/jwks").build();
        decoder.setJwtValidator(JwtValidators.createAtJwtValidator().clientId("reports-client").build());
        return decoder;
    }

    private static boolean trusted(List<String> audiences) {
        return audiences.stream().anyMatch(audience -> audience.endsWith(".example.com"));
    }
}

@RestController
class JwtValidatorFormsController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
